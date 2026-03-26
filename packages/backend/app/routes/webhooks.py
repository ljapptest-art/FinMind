"""
Webhook API Routes.

Provides CRUD operations for webhook subscriptions.
"""

import hashlib
import os
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..extensions import db
from ..models import Webhook, WebhookDelivery, WebhookEventType, WebhookStatus
import logging

bp = Blueprint("webhooks", __name__)
logger = logging.getLogger("finmind.webhooks")

# All available event types
ALL_EVENT_TYPES = [e.value for e in WebhookEventType]


def _generate_secret() -> str:
    """Generate a secure random secret for webhook signing."""
    return hashlib.sha256(os.urandom(32)).hexdigest()


def _webhook_to_dict(webhook: Webhook) -> dict:
    """Convert webhook model to dict for API response."""
    return {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.get_events(),
        "status": webhook.status,
        "description": webhook.description,
        "created_at": webhook.created_at.isoformat() + "Z",
        "updated_at": webhook.updated_at.isoformat() + "Z",
    }


def _delivery_to_dict(delivery: WebhookDelivery) -> dict:
    """Convert delivery model to dict for API response."""
    return {
        "id": delivery.id,
        "webhook_id": delivery.webhook_id,
        "event_type": delivery.event_type,
        "status": delivery.status,
        "attempt_count": delivery.attempt_count,
        "max_attempts": delivery.max_attempts,
        "http_status": delivery.http_status,
        "last_error": delivery.last_error,
        "created_at": delivery.created_at.isoformat() + "Z",
        "delivered_at": delivery.delivered_at.isoformat() + "Z" if delivery.delivered_at else None,
        "next_retry_at": delivery.next_retry_at.isoformat() + "Z" if delivery.next_retry_at else None,
    }


@bp.get("/events")
def list_event_types():
    """
    List all available webhook event types.
    
    Returns:
        JSON array of event type strings with descriptions.
    """
    event_descriptions = {
        WebhookEventType.USER_REGISTERED.value: "Triggered when a new user registers",
        WebhookEventType.USER_LOGIN.value: "Triggered when a user logs in",
        WebhookEventType.EXPENSE_CREATED.value: "Triggered when an expense is created",
        WebhookEventType.EXPENSE_UPDATED.value: "Triggered when an expense is updated",
        WebhookEventType.EXPENSE_DELETED.value: "Triggered when an expense is deleted",
        WebhookEventType.BILL_CREATED.value: "Triggered when a bill is created",
        WebhookEventType.BILL_PAID.value: "Triggered when a bill is marked as paid",
        WebhookEventType.BILL_DELETED.value: "Triggered when a bill is deleted",
        WebhookEventType.CATEGORY_CREATED.value: "Triggered when a category is created",
        WebhookEventType.RECURRING_EXPENSE_CREATED.value: "Triggered when a recurring expense is created",
    }
    
    return jsonify([
        {"type": event, "description": event_descriptions.get(event, "")}
        for event in ALL_EVENT_TYPES
    ])


@bp.get("")
@jwt_required()
def list_webhooks():
    """
    List all webhooks for the authenticated user.
    
    Returns:
        JSON array of webhook objects.
    """
    uid = int(get_jwt_identity())
    webhooks = (
        db.session.query(Webhook)
        .filter_by(user_id=uid)
        .order_by(Webhook.created_at.desc())
        .all()
    )
    logger.info("List webhooks user=%s count=%s", uid, len(webhooks))
    return jsonify([_webhook_to_dict(w) for w in webhooks])


@bp.post("")
@jwt_required()
def create_webhook():
    """
    Create a new webhook subscription.
    
    Request body:
        {
            "url": "https://example.com/webhook",
            "events": ["expense.created", "bill.paid"],
            "description": "Optional description"
        }
    
    The `events` array can contain specific event types or ["*"] for all events.
    A secret will be auto-generated for signing webhooks.
    
    Returns:
        Created webhook object with the generated secret.
        IMPORTANT: The secret is only shown once upon creation.
    """
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    
    # Validate URL
    url = data.get("url", "").strip()
    if not url:
        return jsonify(error="url is required"), 400
    if not url.startswith(("http://", "https://")):
        return jsonify(error="url must start with http:// or https://"), 400
    
    # Validate events
    events = data.get("events", [])
    if not isinstance(events, list) or not events:
        return jsonify(error="events must be a non-empty array"), 400
    
    # Validate each event type
    for event in events:
        if event != "*" and event not in ALL_EVENT_TYPES:
            return jsonify(error=f"invalid event type: {event}"), 400
    
    # Generate secret
    secret = _generate_secret()
    
    # Create webhook
    webhook = Webhook(
        user_id=uid,
        url=url,
        secret=secret,
        description=data.get("description", "").strip() or None,
    )
    webhook.set_events(events)
    
    db.session.add(webhook)
    db.session.commit()
    
    logger.info("Created webhook id=%s user=%s url=%s events=%s", webhook.id, uid, url, events)
    
    # Return webhook with secret (only time it's shown)
    result = _webhook_to_dict(webhook)
    result["secret"] = secret
    
    return jsonify(result), 201


@bp.get("/<int:webhook_id>")
@jwt_required()
def get_webhook(webhook_id: int):
    """
    Get a specific webhook by ID.
    
    Returns:
        Webhook object (without the secret).
    """
    uid = int(get_jwt_identity())
    webhook = db.session.get(Webhook, webhook_id)
    
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    return jsonify(_webhook_to_dict(webhook))


@bp.patch("/<int:webhook_id>")
@jwt_required()
def update_webhook(webhook_id: int):
    """
    Update a webhook subscription.
    
    Request body (all fields optional):
        {
            "url": "https://new-url.com/webhook",
            "events": ["expense.created"],
            "status": "active" or "disabled",
            "description": "Updated description"
        }
    
    Returns:
        Updated webhook object.
    """
    uid = int(get_jwt_identity())
    webhook = db.session.get(Webhook, webhook_id)
    
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    data = request.get_json() or {}
    
    if "url" in data:
        url = data["url"].strip()
        if not url.startswith(("http://", "https://")):
            return jsonify(error="url must start with http:// or https://"), 400
        webhook.url = url
    
    if "events" in data:
        events = data["events"]
        if not isinstance(events, list) or not events:
            return jsonify(error="events must be a non-empty array"), 400
        for event in events:
            if event != "*" and event not in ALL_EVENT_TYPES:
                return jsonify(error=f"invalid event type: {event}"), 400
        webhook.set_events(events)
    
    if "status" in data:
        status = data["status"]
        if status not in [WebhookStatus.ACTIVE.value, WebhookStatus.DISABLED.value]:
            return jsonify(error="status must be 'active' or 'disabled'"), 400
        webhook.status = status
    
    if "description" in data:
        webhook.description = data["description"].strip() or None
    
    db.session.commit()
    
    logger.info("Updated webhook id=%s user=%s", webhook_id, uid)
    
    return jsonify(_webhook_to_dict(webhook))


@bp.delete("/<int:webhook_id>")
@jwt_required()
def delete_webhook(webhook_id: int):
    """
    Delete a webhook subscription.
    
    Also deletes all associated delivery records.
    
    Returns:
        Success message.
    """
    uid = int(get_jwt_identity())
    webhook = db.session.get(Webhook, webhook_id)
    
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    # Delete associated deliveries
    db.session.query(WebhookDelivery).filter_by(webhook_id=webhook_id).delete()
    
    # Delete webhook
    db.session.delete(webhook)
    db.session.commit()
    
    logger.info("Deleted webhook id=%s user=%s", webhook_id, uid)
    
    return jsonify(message="deleted")


@bp.post("/<int:webhook_id>/regenerate-secret")
@jwt_required()
def regenerate_secret(webhook_id: int):
    """
    Regenerate the webhook signing secret.
    
    IMPORTANT: The previous secret will immediately become invalid.
    The new secret is only shown once.
    
    Returns:
        Webhook object with the new secret.
    """
    uid = int(get_jwt_identity())
    webhook = db.session.get(Webhook, webhook_id)
    
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    # Generate new secret
    new_secret = _generate_secret()
    webhook.secret = new_secret
    db.session.commit()
    
    logger.info("Regenerated secret for webhook id=%s user=%s", webhook_id, uid)
    
    result = _webhook_to_dict(webhook)
    result["secret"] = new_secret
    
    return jsonify(result)


@bp.get("/<int:webhook_id>/deliveries")
@jwt_required()
def list_deliveries(webhook_id: int):
    """
    List delivery attempts for a webhook.
    
    Query params:
        status: Filter by status (pending, success, failed, retrying)
        limit: Max results (default 50, max 200)
    
    Returns:
        JSON array of delivery objects.
    """
    uid = int(get_jwt_identity())
    webhook = db.session.get(Webhook, webhook_id)
    
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    query = db.session.query(WebhookDelivery).filter_by(webhook_id=webhook_id)
    
    status_filter = request.args.get("status")
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        limit = 50
    
    deliveries = (
        query
        .order_by(WebhookDelivery.created_at.desc())
        .limit(limit)
        .all()
    )
    
    return jsonify([_delivery_to_dict(d) for d in deliveries])


@bp.get("/deliveries/<int:delivery_id>")
@jwt_required()
def get_delivery(delivery_id: int):
    """
    Get details of a specific delivery attempt.
    
    Returns:
        Delivery object with full payload and signature.
    """
    uid = int(get_jwt_identity())
    delivery = db.session.get(WebhookDelivery, delivery_id)
    
    if not delivery:
        return jsonify(error="not found"), 404
    
    # Verify ownership through webhook
    webhook = db.session.get(Webhook, delivery.webhook_id)
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    result = _delivery_to_dict(delivery)
    result["payload"] = delivery.payload
    result["signature"] = delivery.signature
    
    return jsonify(result)


@bp.post("/deliveries/<int:delivery_id>/retry")
@jwt_required()
def retry_delivery(delivery_id: int):
    """
    Manually retry a failed delivery.
    
    Resets attempt count and attempts immediate delivery.
    
    Returns:
        Updated delivery object.
    """
    from ..services.webhooks import _deliver_webhook
    
    uid = int(get_jwt_identity())
    delivery = db.session.get(WebhookDelivery, delivery_id)
    
    if not delivery:
        return jsonify(error="not found"), 404
    
    # Verify ownership through webhook
    webhook = db.session.get(Webhook, delivery.webhook_id)
    if not webhook or webhook.user_id != uid:
        return jsonify(error="not found"), 404
    
    if delivery.status == DeliveryStatus.SUCCESS.value:
        return jsonify(error="cannot retry successful delivery"), 400
    
    # Reset for retry
    delivery.status = DeliveryStatus.PENDING.value
    delivery.next_retry_at = None
    
    # Attempt delivery
    _deliver_webhook(delivery, webhook)
    
    logger.info("Manual retry for delivery id=%s status=%s", delivery_id, delivery.status)
    
    return jsonify(_delivery_to_dict(delivery))


# Need to import DeliveryStatus for the retry endpoint
from ..models import DeliveryStatus
