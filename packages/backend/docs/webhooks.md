# Webhook Event System

FinMind provides a webhook system for integrating with external services. Webhooks are HTTP callbacks that deliver event data to your application when specific actions occur in FinMind.

## Features

- **Signed delivery** - All webhooks are signed using HMAC-SHA256 for verification
- **Automatic retries** - Failed deliveries are retried with exponential backoff
- **Event filtering** - Subscribe to specific events or all events
- **Delivery tracking** - Monitor delivery status and history

## Quick Start

### 1. Create a Webhook Subscription

```bash
curl -X POST https://api.finmind.com/webhooks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-server.com/webhooks/finmind",
    "events": ["expense.created", "bill.paid"],
    "description": "My webhook integration"
  }'
```

Response:
```json
{
  "id": 1,
  "url": "https://your-server.com/webhooks/finmind",
  "events": ["expense.created", "bill.paid"],
  "status": "active",
  "secret": "a1b2c3d4e5f6...",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Important**: Save the `secret` value! It's only shown once and is required to verify webhook signatures.

### 2. Verify Webhook Signatures

Every webhook request includes these headers:

| Header | Description |
|--------|-------------|
| `X-Webhook-Signature` | HMAC-SHA256 signature |
| `X-Webhook-Timestamp` | ISO 8601 timestamp |
| `X-Webhook-Event` | Event type |
| `Content-Type` | `application/json` |

To verify the signature:

```python
import hmac
import hashlib

def verify_webhook(secret: str, payload: str, timestamp: str, signature: str) -> bool:
    """Verify webhook signature."""
    message = f"{timestamp}.{payload}"
    expected = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# Usage
payload = request.body.decode('utf-8')
timestamp = request.headers['X-Webhook-Timestamp']
signature = request.headers['X-Webhook-Signature']

if verify_webhook(YOUR_SECRET, payload, timestamp, signature):
    # Process the webhook
    event = json.loads(payload)
else:
    # Invalid signature - reject
    abort(401)
```

## Event Types

### User Events

| Event | Description | Payload |
|-------|-------------|---------|
| `user.registered` | New user registration | `{user_id, email}` |
| `user.login` | User logged in | `{user_id, email}` |

### Expense Events

| Event | Description | Payload |
|-------|-------------|---------|
| `expense.created` | New expense recorded | `{expense_id, user_id, amount, currency, description, date, expense_type}` |
| `expense.updated` | Expense modified | `{expense_id, user_id, changes: {field: {old, new}}}` |
| `expense.deleted` | Expense removed | `{expense_id, user_id}` |

### Bill Events

| Event | Description | Payload |
|-------|-------------|---------|
| `bill.created` | New bill added | `{bill_id, user_id, name, amount, currency, next_due_date, cadence}` |
| `bill.paid` | Bill marked as paid | `{bill_id, user_id, name, amount, next_due_date}` |
| `bill.deleted` | Bill removed | `{bill_id, user_id}` |

### Category Events

| Event | Description | Payload |
|-------|-------------|---------|
| `category.created` | New category created | `{category_id, user_id, name}` |

### Recurring Expense Events

| Event | Description | Payload |
|-------|-------------|---------|
| `recurring_expense.created` | Recurring expense created | `{recurring_id, user_id, amount, cadence, description, start_date, end_date}` |

## Payload Structure

All webhook payloads follow this structure:

```json
{
  "id": "evt_abc123def456ghi789",
  "type": "expense.created",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "expense_id": 123,
    "user_id": 456,
    "amount": 100.50,
    "currency": "USD",
    "description": "Groceries",
    "date": "2024-01-15",
    "expense_type": "EXPENSE"
  },
  "user_id": 456
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique event ID (format: `evt_` + 24 hex chars) |
| `type` | string | Event type |
| `timestamp` | string | ISO 8601 timestamp when event occurred |
| `data` | object | Event-specific data |
| `user_id` | number | User ID who triggered the event |

## Retry Behavior

When a webhook delivery fails, FinMind automatically retries:

| Attempt | Delay |
|---------|-------|
| 1 (initial) | Immediate |
| 2 | ~1 minute |
| 3 | ~2 minutes |
| 4 | ~4 minutes |
| 5 | ~8 minutes |

After 5 failed attempts, the delivery is marked as failed and no further retries occur.

### Success Criteria

A webhook is considered successful when your server returns:
- HTTP status code `2xx` (200-299)
- Response within 30 seconds

### Manual Retry

You can manually retry failed deliveries:

```bash
curl -X POST https://api.finmind.com/webhooks/deliveries/{delivery_id}/retry \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## API Reference

### List Event Types

```
GET /webhooks/events
```

Returns all available event types with descriptions.

### List Webhooks

```
GET /webhooks
Authorization: Bearer {token}
```

### Create Webhook

```
POST /webhooks
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": string (required),
  "events": string[] (required, use ["*"] for all events),
  "description": string (optional)
}
```

### Get Webhook

```
GET /webhooks/{webhook_id}
Authorization: Bearer {token}
```

### Update Webhook

```
PATCH /webhooks/{webhook_id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": string (optional),
  "events": string[] (optional),
  "status": "active" | "disabled" (optional),
  "description": string (optional)
}
```

### Delete Webhook

```
DELETE /webhooks/{webhook_id}
Authorization: Bearer {token}
```

### Regenerate Secret

```
POST /webhooks/{webhook_id}/regenerate-secret
Authorization: Bearer {token}
```

**Warning**: Previous secret becomes invalid immediately.

### List Deliveries

```
GET /webhooks/{webhook_id}/deliveries?status={status}&limit={limit}
Authorization: Bearer {token}
```

Query parameters:
- `status`: Filter by status (`pending`, `success`, `failed`, `retrying`)
- `limit`: Max results (default: 50, max: 200)

### Get Delivery Details

```
GET /webhooks/deliveries/{delivery_id}
Authorization: Bearer {token}
```

Returns full delivery details including payload and signature.

## Security Best Practices

1. **Always verify signatures** - Never process unverified webhooks
2. **Use HTTPS** - Only use HTTPS URLs for webhook endpoints
3. **Keep secrets secure** - Store webhook secrets securely, never in code
4. **Rotate secrets** - Periodically regenerate webhook secrets
5. **Validate timestamps** - Reject webhooks with old timestamps to prevent replay attacks
6. **Idempotency** - Design your webhook handler to be idempotent (same event processed multiple times yields same result)

## Example Handler

Here's a complete example webhook handler in Python/Flask:

```python
from flask import Flask, request, jsonify, abort
import hmac
import hashlib
import json

app = Flask(__name__)
WEBHOOK_SECRET = "your-webhook-secret"

@app.route("/webhooks/finmind", methods=["POST"])
def handle_webhook():
    # Get headers
    signature = request.headers.get("X-Webhook-Signature")
    timestamp = request.headers.get("X-Webhook-Timestamp")
    event_type = request.headers.get("X-Webhook-Event")
    
    if not signature or not timestamp:
        abort(401, "Missing signature headers")
    
    # Get raw payload
    payload = request.get_data(as_text=True)
    
    # Verify signature
    message = f"{timestamp}.{payload}"
    expected = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected, signature):
        abort(401, "Invalid signature")
    
    # Parse event
    event = json.loads(payload)
    
    # Handle based on event type
    if event["type"] == "expense.created":
        handle_expense_created(event["data"])
    elif event["type"] == "bill.paid":
        handle_bill_paid(event["data"])
    # ... other handlers
    
    return jsonify({"status": "ok"}), 200

def handle_expense_created(data):
    print(f"New expense: {data['amount']} {data['currency']}")
    # Your business logic here

def handle_bill_paid(data):
    print(f"Bill paid: {data['name']}")
    # Your business logic here

if __name__ == "__main__":
    app.run(port=3000)
```

## Troubleshooting

### Webhook not received

1. Check webhook status is `active`
2. Verify your server is publicly accessible
3. Check server logs for incoming requests
4. Verify events are subscribed (or use `["*"]`)

### Signature verification fails

1. Ensure you're using the exact payload (no parsing/re-serialization)
2. Verify the timestamp format
3. Check for whitespace differences

### Timeouts

Your endpoint must respond within 30 seconds. For long-running tasks, return 200 immediately and process asynchronously.
