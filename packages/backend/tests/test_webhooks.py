"""
Tests for Webhook Event System.
Bounty: https://github.com/rohitdash08/FinMind/issues/77
"""

import pytest
import json
import hmac
import hashlib
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

from app.services.webhooks import (
    generate_signature,
    verify_signature,
    calculate_retry_delay,
    _build_payload,
    _send_webhook,
    emit_event,
    get_retries_to_process,
)
from app.models import (
    Webhook,
    WebhookDelivery,
    WebhookEventType,
    WebhookStatus,
    DeliveryStatus,
)


class TestSignatureGeneration:
    """Test HMAC-SHA256 signature generation and verification."""

    def test_generate_signature_basic(self):
        """Test basic signature generation."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created"}'
        timestamp = "2024-01-15T10:30:00Z"
        
        signature = generate_signature(secret, payload, timestamp)
        
        # Should be a hex string
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 produces 64 hex chars
        
        # Verify it's valid hex
        int(signature, 16)

    def test_verify_signature_valid(self):
        """Test signature verification with valid signature."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created"}'
        timestamp = "2024-01-15T10:30:00Z"
        
        signature = generate_signature(secret, payload, timestamp)
        
        assert verify_signature(secret, payload, timestamp, signature) is True

    def test_verify_signature_invalid(self):
        """Test signature verification with invalid signature."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created"}'
        timestamp = "2024-01-15T10:30:00Z"
        
        # Wrong signature
        assert verify_signature(secret, payload, timestamp, "invalid") is False

    def test_verify_signature_wrong_secret(self):
        """Test signature verification with wrong secret."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created"}'
        timestamp = "2024-01-15T10:30:00Z"
        
        signature = generate_signature(secret, payload, timestamp)
        
        # Different secret
        assert verify_signature("wrong-secret", payload, timestamp, signature) is False

    def test_verify_signature_tampered_payload(self):
        """Test that tampered payload fails verification."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created","amount":100}'
        timestamp = "2024-01-15T10:30:00Z"
        
        signature = generate_signature(secret, payload, timestamp)
        
        # Tampered payload
        tampered = '{"type":"expense.created","amount":999}'
        assert verify_signature(secret, tampered, timestamp, signature) is False

    def test_signature_consistency(self):
        """Test that same inputs always produce same signature."""
        secret = "test-secret-key"
        payload = '{"type":"expense.created"}'
        timestamp = "2024-01-15T10:30:00Z"
        
        sig1 = generate_signature(secret, payload, timestamp)
        sig2 = generate_signature(secret, payload, timestamp)
        
        assert sig1 == sig2


class TestRetryLogic:
    """Test exponential backoff retry logic."""

    def test_first_retry_delay(self):
        """Test delay for first retry is ~1 minute."""
        next_retry = calculate_retry_delay(1)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be around 60 seconds (1 minute)
        assert 55 <= delta.total_seconds() <= 65

    def test_second_retry_delay(self):
        """Test delay for second retry is ~2 minutes."""
        next_retry = calculate_retry_delay(2)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be around 120 seconds (2 minutes)
        assert 115 <= delta.total_seconds() <= 125

    def test_third_retry_delay(self):
        """Test delay for third retry is ~4 minutes."""
        next_retry = calculate_retry_delay(3)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be around 240 seconds (4 minutes)
        assert 235 <= delta.total_seconds() <= 245

    def test_fourth_retry_delay(self):
        """Test delay for fourth retry is ~8 minutes."""
        next_retry = calculate_retry_delay(4)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be around 480 seconds (8 minutes)
        assert 475 <= delta.total_seconds() <= 485

    def test_fifth_retry_delay(self):
        """Test delay for fifth retry is ~16 minutes."""
        next_retry = calculate_retry_delay(5)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be around 960 seconds (16 minutes)
        assert 950 <= delta.total_seconds() <= 970

    def test_max_retry_delay(self):
        """Test that very high attempt numbers cap at max delay."""
        next_retry = calculate_retry_delay(100)
        now = datetime.utcnow()
        
        delta = next_retry - now
        # Should be capped at 3600 seconds (1 hour)
        assert delta.total_seconds() <= 3610


class TestPayloadBuilding:
    """Test webhook payload structure."""

    def test_payload_structure(self):
        """Test that payload has all required fields."""
        data = {"expense_id": 123, "amount": 100.50}
        payload = _build_payload("expense.created", data, user_id=1)
        
        assert "id" in payload
        assert payload["id"].startswith("evt_")
        assert payload["type"] == "expense.created"
        assert "timestamp" in payload
        assert payload["data"] == data
        assert payload["user_id"] == 1

    def test_payload_timestamp_format(self):
        """Test timestamp is in ISO 8601 format with Z suffix."""
        payload = _build_payload("expense.created", {})
        
        ts = payload["timestamp"]
        assert ts.endswith("Z")
        # Should be parseable
        datetime.fromisoformat(ts.rstrip("Z"))

    def test_payload_unique_ids(self):
        """Test that each payload gets a unique ID."""
        payload1 = _build_payload("expense.created", {"id": 1})
        payload2 = _build_payload("expense.created", {"id": 2})
        
        assert payload1["id"] != payload2["id"]


class TestSendWebhook:
    """Test HTTP webhook sending."""

    def test_send_webhook_success(self):
        """Test successful webhook delivery."""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 200
        
        with patch("app.services.webhooks.requests.post", return_value=mock_response):
            success, status, error = _send_webhook(
                "https://example.com/webhook",
                "test-secret",
                {"type": "test", "timestamp": "2024-01-15T10:00:00Z", "data": {}}
            )
        
        assert success is True
        assert status == 200
        assert error is None

    def test_send_webhook_failure(self):
        """Test failed webhook delivery."""
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        with patch("app.services.webhooks.requests.post", return_value=mock_response):
            success, status, error = _send_webhook(
                "https://example.com/webhook",
                "test-secret",
                {"type": "test", "timestamp": "2024-01-15T10:00:00Z", "data": {}}
            )
        
        assert success is False
        assert status == 500
        assert "500" in error

    def test_send_webhook_timeout(self):
        """Test webhook timeout handling."""
        import requests
        
        with patch("app.services.webhooks.requests.post", side_effect=requests.Timeout("timeout")):
            success, status, error = _send_webhook(
                "https://example.com/webhook",
                "test-secret",
                {"type": "test", "timestamp": "2024-01-15T10:00:00Z", "data": {}}
            )
        
        assert success is False
        assert status is None
        assert error is not None
        assert "time" in error.lower()

    def test_send_webhook_includes_signature_header(self):
        """Test that webhook includes signature in headers."""
        captured_headers = {}
        
        def capture_post(url, data, headers, **kwargs):
            captured_headers.update(headers)
            mock_response = MagicMock()
            mock_response.ok = True
            mock_response.status_code = 200
            return mock_response
        
        with patch("app.services.webhooks.requests.post", capture_post):
            _send_webhook(
                "https://example.com/webhook",
                "test-secret",
                {"type": "test", "timestamp": "2024-01-15T10:00:00Z", "data": {}}
            )
        
        assert "X-Webhook-Signature" in captured_headers
        assert "X-Webhook-Timestamp" in captured_headers
        assert "X-Webhook-Event" in captured_headers
        assert captured_headers["Content-Type"] == "application/json"

    def test_send_webhook_connection_error(self):
        """Test webhook connection error handling."""
        import requests
        
        with patch("app.services.webhooks.requests.post", side_effect=requests.ConnectionError("connection failed")):
            success, status, error = _send_webhook(
                "https://example.com/webhook",
                "test-secret",
                {"type": "test", "timestamp": "2024-01-15T10:00:00Z", "data": {}}
            )
        
        assert success is False
        assert status is None
        assert error is not None


class TestEventTypes:
    """Test event type definitions."""

    def test_event_types_exist(self):
        """Test that all expected event types are defined."""
        expected_types = [
            "user.registered",
            "user.login",
            "expense.created",
            "expense.updated",
            "expense.deleted",
            "bill.created",
            "bill.paid",
            "bill.deleted",
            "category.created",
            "recurring_expense.created",
        ]
        
        for event_type in expected_types:
            assert hasattr(WebhookEventType, event_type.upper().replace(".", "_").upper())
            assert WebhookEventType(event_type).value == event_type

    def test_event_type_values(self):
        """Test event type enum values."""
        assert WebhookEventType.USER_REGISTERED.value == "user.registered"
        assert WebhookEventType.EXPENSE_CREATED.value == "expense.created"
        assert WebhookEventType.BILL_PAID.value == "bill.paid"


class TestWebhookModel:
    """Test Webhook model methods."""

    def test_get_events_empty(self):
        """Test get_events with empty events."""
        webhook = Webhook(
            user_id=1,
            url="https://example.com",
            secret="secret",
            events=""
        )
        assert webhook.get_events() == []

    def test_get_events_single(self):
        """Test get_events with single event."""
        webhook = Webhook(
            user_id=1,
            url="https://example.com",
            secret="secret",
            events='["expense.created"]'
        )
        assert webhook.get_events() == ["expense.created"]

    def test_get_events_multiple(self):
        """Test get_events with multiple events."""
        webhook = Webhook(
            user_id=1,
            url="https://example.com",
            secret="secret",
            events='["expense.created", "bill.paid"]'
        )
        assert set(webhook.get_events()) == {"expense.created", "bill.paid"}

    def test_set_events(self):
        """Test set_events method."""
        webhook = Webhook(
            user_id=1,
            url="https://example.com",
            secret="secret",
            events=""
        )
        webhook.set_events(["expense.created", "bill.paid"])
        
        parsed = json.loads(webhook.events)
        assert set(parsed) == {"expense.created", "bill.paid"}

    def test_set_events_wildcard(self):
        """Test set_events with wildcard."""
        webhook = Webhook(
            user_id=1,
            url="https://example.com",
            secret="secret",
            events=""
        )
        webhook.set_events(["*"])
        
        assert webhook.get_events() == ["*"]


class TestWebhookStatus:
    """Test webhook status enum."""

    def test_status_values(self):
        """Test webhook status enum values."""
        assert WebhookStatus.ACTIVE.value == "active"
        assert WebhookStatus.DISABLED.value == "disabled"

    def test_delivery_status_values(self):
        """Test delivery status enum values."""
        assert DeliveryStatus.PENDING.value == "pending"
        assert DeliveryStatus.SUCCESS.value == "success"
        assert DeliveryStatus.FAILED.value == "failed"
        assert DeliveryStatus.RETRYING.value == "retrying"
