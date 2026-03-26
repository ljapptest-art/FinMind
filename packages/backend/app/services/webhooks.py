"""
Webhook Event System for FinMind.

Provides signed webhook delivery with HMAC-SHA256 signatures,
exponential backoff retry, and comprehensive event tracking.
"""

import hashlib
import hmac
import json
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Any, Callable
from flask import current_app
import requests

from ..extensions import db
from ..models import (
    Webhook,
    WebhookDelivery,
    WebhookEventType,
    WebhookStatus,
    DeliveryStatus,
)

logger = logging.getLogger("finmind.webhooks")

# Retry configuration
MAX_RETRIES = 5
INITIAL_RETRY_DELAY_SECONDS = 60  # 1 minute
MAX_RETRY_DELAY_SECONDS = 3600  # 1 hour
REQUEST_TIMEOUT_SECONDS = 30


def generate_signature(secret: str, payload: str, timestamp: str) -> str:
    """
    Generate HMAC-SHA256 signature for webhook payload.
    
    The signature is computed over: timestamp + "." + payload
    This prevents replay attacks by including the timestamp.
    
    Args:
        secret: The webhook secret key
        payload: The JSON payload string
        timestamp: ISO 8601 timestamp string
        
    Returns:
        Hex-encoded signature string
    """
    message = f"{timestamp}.{payload}"
    signature = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_signature(secret: str, payload: str, timestamp: str, signature: str) -> bool:
    """
    Verify a webhook signature.
    
    Args:
        secret: The webhook secret key
        payload: The JSON payload string
        timestamp: ISO 8601 timestamp string
        signature: The signature to verify
        
    Returns:
        True if signature is valid, False otherwise
    """
    expected = generate_signature(secret, payload, timestamp)
    return hmac.compare_digest(expected, signature)


def calculate_retry_delay(attempt: int) -> datetime:
    """
    Calculate next retry time using exponential backoff.
    
    Delay formula: min(INITIAL * 2^(attempt-1), MAX)
    
    Attempts:  1   2    3     4      5
    Delay:    60  120  240   480    960 seconds
    
    Args:
        attempt: Current attempt number (1-indexed)
        
    Returns:
        Datetime when next retry should occur
    """
    delay = min(
        INITIAL_RETRY_DELAY_SECONDS * (2 ** (attempt - 1)),
        MAX_RETRY_DELAY_SECONDS
    )
    return datetime.utcnow() + timedelta(seconds=delay)


def get_retries_to_process() -> list[WebhookDelivery]:
    """
    Get all pending deliveries that are ready for retry.
    
    Returns deliveries where:
    - status is RETRYING
    - next_retry_at is in the past
    - attempt_count < max_attempts
    """
    now = datetime.utcnow()
    return (
        db.session.query(WebhookDelivery)
        .filter(
            WebhookDelivery.status == DeliveryStatus.RETRYING.value,
            WebhookDelivery.next_retry_at <= now,
            WebhookDelivery.attempt_count < WebhookDelivery.max_attempts
        )
        .all()
    )


def _build_payload(
    event_type: str,
    data: dict[str, Any],
    user_id: int | None = None
) -> dict[str, Any]:
    """
    Build a standardized webhook payload.
    
    Payload structure:
    {
        "id": "evt_<uuid>",
        "type": "expense.created",
        "timestamp": "2024-01-15T10:30:00Z",
        "data": { ... event-specific data ... },
        "user_id": 123
    }
    """
    import uuid
    return {
        "id": f"evt_{uuid.uuid4().hex[:24]}",
        "type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data": data,
        "user_id": user_id
    }


def _send_webhook(
    url: str,
    secret: str,
    payload: dict[str, Any]
) -> tuple[bool, int | None, str | None]:
    """
    Send a webhook request with signature.
    
    Args:
        url: Target webhook URL
        secret: Signing secret
        payload: Event payload dict
        
    Returns:
        Tuple of (success, http_status, error_message)
    """
    payload_json = json.dumps(payload, separators=(",", ":"))
    timestamp = payload["timestamp"]
    signature = generate_signature(secret, payload_json, timestamp)
    
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Event": payload["type"],
        "User-Agent": "FinMind-Webhook/1.0"
    }
    
    try:
        response = requests.post(
            url,
            data=payload_json,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS
        )
        
        if response.ok:
            return True, response.status_code, None
        else:
            error = f"HTTP {response.status_code}: {response.text[:500]}"
            return False, response.status_code, error
            
    except requests.Timeout:
        return False, None, "Request timed out"
    except requests.RequestException as e:
        return False, None, str(e)


def _deliver_webhook(delivery: WebhookDelivery, webhook: Webhook) -> None:
    """
    Attempt to deliver a webhook, handling retries on failure.
    """
    try:
        payload = json.loads(delivery.payload)
    except json.JSONDecodeError:
        delivery.status = DeliveryStatus.FAILED.value
        delivery.last_error = "Invalid payload JSON"
        delivery.delivered_at = datetime.utcnow()
        db.session.commit()
        return
    
    success, http_status, error = _send_webhook(
        webhook.url,
        webhook.secret,
        payload
    )
    
    delivery.attempt_count += 1
    delivery.http_status = http_status
    
    if success:
        delivery.status = DeliveryStatus.SUCCESS.value
        delivery.delivered_at = datetime.utcnow()
        logger.info(
            "Webhook delivered: webhook_id=%s delivery_id=%s event=%s attempts=%s",
            webhook.id, delivery.id, delivery.event_type, delivery.attempt_count
        )
    elif delivery.attempt_count >= delivery.max_attempts:
        delivery.status = DeliveryStatus.FAILED.value
        delivery.last_error = error
        delivery.delivered_at = datetime.utcnow()
        logger.warning(
            "Webhook delivery failed (max retries): webhook_id=%s delivery_id=%s error=%s",
            webhook.id, delivery.id, error
        )
    else:
        delivery.status = DeliveryStatus.RETRYING.value
        delivery.last_error = error
        delivery.next_retry_at = calculate_retry_delay(delivery.attempt_count)
        logger.info(
            "Webhook delivery failed, will retry: webhook_id=%s delivery_id=%s attempt=%s next_retry=%s",
            webhook.id, delivery.id, delivery.attempt_count, delivery.next_retry_at
        )
    
    db.session.commit()


def emit_event(
    event_type: str,
    data: dict[str, Any],
    user_id: int | None = None
) -> list[WebhookDelivery]:
    """
    Emit a webhook event to all subscribed webhooks.
    
    Finds all active webhooks subscribed to the event type
    and creates delivery records for each.
    
    Args:
        event_type: Event type from WebhookEventType enum
        data: Event-specific data
        user_id: Optional user ID to filter webhooks
        
    Returns:
        List of created WebhookDelivery records
    """
    # Build the standardized payload
    payload = _build_payload(event_type, data, user_id)
    payload_json = json.dumps(payload, separators=(",", ":"))
    timestamp = payload["timestamp"]
    
    # Find matching webhooks
    query = db.session.query(Webhook).filter(
        Webhook.status == WebhookStatus.ACTIVE.value
    )
    
    if user_id is not None:
        query = query.filter(Webhook.user_id == user_id)
    
    webhooks = query.all()
    
    deliveries = []
    for webhook in webhooks:
        # Check if webhook is subscribed to this event type
        subscribed_events = webhook.get_events()
        if "*" not in subscribed_events and event_type not in subscribed_events:
            continue
        
        # Generate signature
        signature = generate_signature(webhook.secret, payload_json, timestamp)
        
        # Create delivery record
        delivery = WebhookDelivery(
            webhook_id=webhook.id,
            event_type=event_type,
            payload=payload_json,
            signature=signature,
            status=DeliveryStatus.PENDING.value,
            attempt_count=0,
            max_attempts=MAX_RETRIES
        )
        db.session.add(delivery)
        deliveries.append(delivery)
    
    if deliveries:
        db.session.commit()
        logger.info(
            "Created %s webhook deliveries for event %s",
            len(deliveries), event_type
        )
    
    # Trigger async delivery (in background thread for development)
    # In production, this should be handled by a proper task queue
    for delivery in deliveries:
        webhook = db.session.get(Webhook, delivery.webhook_id)
        if webhook:
            _deliver_webhook(delivery, webhook)
    
    return deliveries


def process_pending_retries() -> int:
    """
    Process all pending webhook retries.
    
    This should be called periodically by a scheduler.
    
    Returns:
        Number of deliveries processed
    """
    deliveries = get_retries_to_process()
    for delivery in deliveries:
        webhook = db.session.get(Webhook, delivery.webhook_id)
        if webhook and webhook.status == WebhookStatus.ACTIVE.value:
            _deliver_webhook(delivery, webhook)
    return len(deliveries)


# Convenience functions for common events

def emit_user_registered(user_id: int, email: str) -> list[WebhookDelivery]:
    """Emit user.registered event."""
    return emit_event(
        WebhookEventType.USER_REGISTERED.value,
        {"user_id": user_id, "email": email},
        user_id
    )


def emit_user_login(user_id: int, email: str) -> list[WebhookDelivery]:
    """Emit user.login event."""
    return emit_event(
        WebhookEventType.USER_LOGIN.value,
        {"user_id": user_id, "email": email},
        user_id
    )


def emit_expense_created(
    expense_id: int,
    user_id: int,
    amount: float,
    currency: str,
    description: str,
    **kwargs
) -> list[WebhookDelivery]:
    """Emit expense.created event."""
    return emit_event(
        WebhookEventType.EXPENSE_CREATED.value,
        {
            "expense_id": expense_id,
            "user_id": user_id,
            "amount": amount,
            "currency": currency,
            "description": description,
            **kwargs
        },
        user_id
    )


def emit_expense_updated(
    expense_id: int,
    user_id: int,
    changes: dict[str, Any]
) -> list[WebhookDelivery]:
    """Emit expense.updated event."""
    return emit_event(
        WebhookEventType.EXPENSE_UPDATED.value,
        {
            "expense_id": expense_id,
            "user_id": user_id,
            "changes": changes
        },
        user_id
    )


def emit_expense_deleted(expense_id: int, user_id: int) -> list[WebhookDelivery]:
    """Emit expense.deleted event."""
    return emit_event(
        WebhookEventType.EXPENSE_DELETED.value,
        {"expense_id": expense_id, "user_id": user_id},
        user_id
    )


def emit_bill_created(
    bill_id: int,
    user_id: int,
    name: str,
    amount: float,
    currency: str,
    **kwargs
) -> list[WebhookDelivery]:
    """Emit bill.created event."""
    return emit_event(
        WebhookEventType.BILL_CREATED.value,
        {
            "bill_id": bill_id,
            "user_id": user_id,
            "name": name,
            "amount": amount,
            "currency": currency,
            **kwargs
        },
        user_id
    )


def emit_bill_paid(
    bill_id: int,
    user_id: int,
    name: str,
    amount: float,
    next_due_date: str | None
) -> list[WebhookDelivery]:
    """Emit bill.paid event."""
    return emit_event(
        WebhookEventType.BILL_PAID.value,
        {
            "bill_id": bill_id,
            "user_id": user_id,
            "name": name,
            "amount": amount,
            "next_due_date": next_due_date
        },
        user_id
    )


def emit_bill_deleted(bill_id: int, user_id: int) -> list[WebhookDelivery]:
    """Emit bill.deleted event."""
    return emit_event(
        WebhookEventType.BILL_DELETED.value,
        {"bill_id": bill_id, "user_id": user_id},
        user_id
    )


def emit_category_created(
    category_id: int,
    user_id: int,
    name: str
) -> list[WebhookDelivery]:
    """Emit category.created event."""
    return emit_event(
        WebhookEventType.CATEGORY_CREATED.value,
        {"category_id": category_id, "user_id": user_id, "name": name},
        user_id
    )


def emit_recurring_expense_created(
    recurring_id: int,
    user_id: int,
    amount: float,
    cadence: str,
    description: str,
    **kwargs
) -> list[WebhookDelivery]:
    """Emit recurring_expense.created event."""
    return emit_event(
        WebhookEventType.RECURRING_EXPENSE_CREATED.value,
        {
            "recurring_id": recurring_id,
            "user_id": user_id,
            "amount": amount,
            "cadence": cadence,
            "description": description,
            **kwargs
        },
        user_id
    )
