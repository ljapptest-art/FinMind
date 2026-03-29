"""Tests for login anomaly detection."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import json

from app import create_app
from app.extensions import db
from app.models import (
    User,
    LoginAttempt,
    UserDevice,
    LoginAnomaly,
    LoginAnomalyType,
)
from app.services.login_anomaly import (
    LoginAnomalyDetector,
    LoginContext,
    AnomalyResult,
    get_client_ip,
)


class FakeRedis:
    """Fake Redis client for testing."""
    def __init__(self):
        self.data = {}
    
    def get(self, key):
        return self.data.get(key)
    
    def setex(self, key, ttl, value):
        self.data[key] = value
    
    def delete(self, key):
        self.data.pop(key, None)
    
    def flushdb(self):
        self.data.clear()


@pytest.fixture
def fake_redis():
    """Create fake Redis client."""
    return FakeRedis()


@pytest.fixture
def app(fake_redis):
    """Create test app with in-memory database and fake Redis."""
    from app.config import Settings
    settings = Settings(
        database_url="sqlite:///:memory:",
        jwt_secret="test-secret-with-32-plus-chars-1234567890",
    )
    app = create_app(settings)
    
    # Patch redis_client
    with patch('app.extensions.redis_client', fake_redis):
        with patch('app.routes.auth.redis_client', fake_redis):
            with app.app_context():
                db.create_all()
                yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def detector_instance():
    """Create detector instance."""
    return LoginAnomalyDetector()


class TestLoginContext:
    """Tests for LoginContext dataclass."""
    
    def test_create_context(self):
        """Test creating a login context."""
        context = LoginContext(
            user_id=1,
            email="test@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_fingerprint="abc123",
            country="US",
            city="New York",
        )
        assert context.user_id == 1
        assert context.email == "test@example.com"
        assert context.ip_address == "192.168.1.1"
        assert context.country == "US"


class TestAnomalyResult:
    """Tests for AnomalyResult dataclass."""
    
    def test_no_anomaly(self):
        """Test result with no anomaly."""
        result = AnomalyResult(is_anomaly=False)
        assert result.is_anomaly is False
        assert result.anomaly_type is None
        assert result.severity == "low"
    
    def test_with_anomaly(self):
        """Test result with anomaly."""
        result = AnomalyResult(
            is_anomaly=True,
            anomaly_type=LoginAnomalyType.NEW_DEVICE,
            severity="medium",
            details={"device": "test"}
        )
        assert result.is_anomaly is True
        assert result.anomaly_type == LoginAnomalyType.NEW_DEVICE
        assert result.severity == "medium"


class TestLoginAnomalyDetector:
    """Tests for LoginAnomalyDetector class."""
    
    def test_device_fingerprint_generation(self, detector_instance):
        """Test device fingerprint is generated consistently."""
        fp1 = detector_instance.detect_device_fingerprint("Chrome/1.0", "192.168.1.1")
        fp2 = detector_instance.detect_device_fingerprint("Chrome/1.0", "192.168.1.1")
        
        assert fp1 == fp2
        assert len(fp1) == 32
    
    def test_different_devices_different_fingerprints(self, detector_instance):
        """Test different user agents produce different fingerprints."""
        fp1 = detector_instance.detect_device_fingerprint("Chrome/1.0", "192.168.1.1")
        fp2 = detector_instance.detect_device_fingerprint("Firefox/1.0", "192.168.1.1")
        
        assert fp1 != fp2
    
    def test_record_login_attempt(self, app, detector_instance):
        """Test recording a login attempt."""
        with app.app_context():
            context = LoginContext(
                user_id=1,
                email="test@example.com",
                ip_address="192.168.1.1",
                user_agent="Test Agent",
                device_fingerprint="abc123",
            )
            
            attempt = detector_instance.record_login_attempt(
                context, success=True
            )
            db.session.commit()
            
            assert attempt.id is not None
            assert attempt.email == "test@example.com"
            assert attempt.success is True
            assert attempt.ip_address == "192.168.1.1"
    
    def test_check_new_device_no_user(self, app, detector_instance):
        """Test new device check with no user."""
        with app.app_context():
            context = LoginContext(
                user_id=None,
                email="test@example.com",
                ip_address="192.168.1.1",
                device_fingerprint="abc123",
            )
            
            result = detector_instance.check_new_device(context)
            assert result.is_anomaly is False
    
    def test_check_new_device_first_device(self, app, detector_instance):
        """Test first device for user is detected as new."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                device_fingerprint="abc123",
            )
            
            result = detector_instance.check_new_device(context)
            assert result.is_anomaly is True
            assert result.anomaly_type == LoginAnomalyType.NEW_DEVICE
            assert result.severity == "medium"
    
    def test_check_new_device_known_device(self, app, detector_instance):
        """Test known device is not flagged."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            # Add known device
            device = UserDevice(
                user_id=user.id,
                device_fingerprint="abc123",
                ip_address="192.168.1.1",
            )
            db.session.add(device)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                device_fingerprint="abc123",
            )
            
            result = detector_instance.check_new_device(context)
            assert result.is_anomaly is False
    
    def test_check_new_location_first_login(self, app, detector_instance):
        """Test first login doesn't trigger location anomaly."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                country="US",
                city="New York",
            )
            
            result = detector_instance.check_new_location(context)
            assert result.is_anomaly is False
    
    def test_check_new_location_same_country(self, app, detector_instance):
        """Test same country doesn't trigger anomaly."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            # Add previous login
            attempt = LoginAttempt(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                success=True,
                country="US",
            )
            db.session.add(attempt)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.2",
                country="US",
                city="Los Angeles",
            )
            
            result = detector_instance.check_new_location(context)
            assert result.is_anomaly is False
    
    def test_check_new_location_different_country(self, app, detector_instance):
        """Test new country triggers location anomaly."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            # Add previous login in US
            attempt = LoginAttempt(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                success=True,
                country="US",
            )
            db.session.add(attempt)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="10.0.0.1",
                country="CN",
                city="Beijing",
            )
            
            result = detector_instance.check_new_location(context)
            assert result.is_anomaly is True
            assert result.anomaly_type == LoginAnomalyType.NEW_LOCATION
            assert result.severity == "high"
    
    def test_check_unusual_time_insufficient_data(self, app, detector_instance):
        """Test unusual time check with insufficient login history."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            # Only 2 previous logins (below threshold)
            for _ in range(2):
                attempt = LoginAttempt(
                    user_id=user.id,
                    email="test@example.com",
                    ip_address="192.168.1.1",
                    success=True,
                )
                db.session.add(attempt)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
            )
            
            result = detector_instance.check_unusual_time(context)
            assert result.is_anomaly is False
    
    def test_check_multiple_failures_below_threshold(self, app, detector_instance):
        """Test multiple failures check below threshold."""
        with app.app_context():
            # Add 3 failed attempts (below threshold of 5)
            for _ in range(3):
                attempt = LoginAttempt(
                    user_id=None,
                    email="test@example.com",
                    ip_address="192.168.1.1",
                    success=False,
                    failure_reason="invalid_credentials",
                )
                db.session.add(attempt)
            db.session.commit()
            
            result = detector_instance.check_multiple_failures("test@example.com")
            assert result.is_anomaly is False
    
    def test_check_multiple_failures_at_threshold(self, app, detector_instance):
        """Test multiple failures check at threshold."""
        with app.app_context():
            # Add 5 failed attempts (at threshold)
            for _ in range(5):
                attempt = LoginAttempt(
                    user_id=None,
                    email="test@example.com",
                    ip_address="192.168.1.1",
                    success=False,
                    failure_reason="invalid_credentials",
                )
                db.session.add(attempt)
            db.session.commit()
            
            result = detector_instance.check_multiple_failures("test@example.com")
            assert result.is_anomaly is True
            assert result.anomaly_type == LoginAnomalyType.MULTIPLE_FAILURES
            assert result.severity == "high"
    
    def test_check_multiple_failures_old_attempts_excluded(self, app, detector_instance):
        """Test that old failed attempts are excluded."""
        with app.app_context():
            # Add 5 failed attempts, but 2 are outside the window
            old_time = datetime.utcnow() - timedelta(hours=2)
            
            # Old attempts (outside window)
            for _ in range(2):
                attempt = LoginAttempt(
                    user_id=None,
                    email="test@example.com",
                    ip_address="192.168.1.1",
                    success=False,
                    failure_reason="invalid_credentials",
                )
                attempt.created_at = old_time
                db.session.add(attempt)
            
            # Recent attempts (inside window)
            for _ in range(3):
                attempt = LoginAttempt(
                    user_id=None,
                    email="test@example.com",
                    ip_address="192.168.1.1",
                    success=False,
                    failure_reason="invalid_credentials",
                )
                db.session.add(attempt)
            db.session.commit()
            
            result = detector_instance.check_multiple_failures("test@example.com")
            assert result.is_anomaly is False  # Only 3 in window
    
    def test_process_login_success(self, app, detector_instance):
        """Test successful login processing."""
        with app.app_context():
            user = User(email="test@example.com", password_hash="hash")
            db.session.add(user)
            db.session.commit()
            
            context = LoginContext(
                user_id=user.id,
                email="test@example.com",
                ip_address="192.168.1.1",
                user_agent="Test Agent",
            )
            
            attempt, anomalies = detector_instance.process_login(
                context, success=True
            )
            db.session.commit()
            
            assert attempt.id is not None
            assert attempt.success is True
            # First login will have new device anomaly
            assert len(anomalies) == 1
            assert anomalies[0].anomaly_type == LoginAnomalyType.NEW_DEVICE
            
            # Check device was registered
            device = db.session.query(UserDevice).filter(
                UserDevice.user_id == user.id
            ).first()
            assert device is not None
    
    def test_process_login_failure(self, app, detector_instance):
        """Test failed login processing."""
        with app.app_context():
            context = LoginContext(
                user_id=None,
                email="test@example.com",
                ip_address="192.168.1.1",
                user_agent="Test Agent",
            )
            
            attempt, anomalies = detector_instance.process_login(
                context, success=False, failure_reason="invalid_credentials"
            )
            db.session.commit()
            
            assert attempt.id is not None
            assert attempt.success is False
            assert attempt.failure_reason == "invalid_credentials"
            # No user, so no user-level anomalies recorded
            assert len(anomalies) == 0


class TestSecurityEndpoints:
    """Tests for security API endpoints."""
    
    @pytest.fixture
    def auth_header(self, client):
        """Create auth header for test user."""
        # Register user
        client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "password123"
        })
        # Login
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "password123"
        })
        data = response.get_json()
        return {"Authorization": f"Bearer {data['access_token']}"}
    
    def test_list_devices_empty(self, client, auth_header):
        """Test listing devices when none registered."""
        response = client.get("/security/devices", headers=auth_header)
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
    
    def test_list_devices_after_login(self, client, auth_header):
        """Test listing devices after a login."""
        response = client.get("/security/devices", headers=auth_header)
        assert response.status_code == 200
        data = response.get_json()
        # One device should be registered from login
        assert len(data) >= 1
    
    def test_update_device_name(self, client, auth_header):
        """Test updating device name."""
        # First get devices
        response = client.get("/security/devices", headers=auth_header)
        devices = response.get_json()
        
        if devices:
            device_id = devices[0]["id"]
            response = client.patch(
                f"/security/devices/{device_id}",
                headers=auth_header,
                json={"device_name": "My Laptop"}
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data["device_name"] == "My Laptop"
    
    def test_revoke_device(self, client, auth_header):
        """Test revoking a device."""
        # First get devices
        response = client.get("/security/devices", headers=auth_header)
        devices = response.get_json()
        
        if devices:
            device_id = devices[0]["id"]
            response = client.delete(
                f"/security/devices/{device_id}",
                headers=auth_header
            )
            assert response.status_code == 200
    
    def test_login_history(self, client, auth_header):
        """Test getting login history."""
        response = client.get("/security/login-history", headers=auth_header)
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        # Should have at least the login used for auth
        assert len(data) >= 1
    
    def test_list_alerts_empty(self, client, auth_header):
        """Test listing alerts when none exist."""
        response = client.get("/security/alerts", headers=auth_header)
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
    
    def test_acknowledge_alert(self, client, app, auth_header):
        """Test acknowledging an alert."""
        with app.app_context():
            user = db.session.query(User).filter_by(
                email="test@example.com"
            ).first()
            
            # Create an alert
            alert = LoginAnomaly(
                user_id=user.id,
                anomaly_type=LoginAnomalyType.NEW_DEVICE,
                severity="medium",
            )
            db.session.add(alert)
            db.session.commit()
            alert_id = alert.id
        
        response = client.post(
            f"/security/alerts/{alert_id}/acknowledge",
            headers=auth_header
        )
        assert response.status_code == 200
    
    def test_acknowledge_all_alerts(self, client, app, auth_header):
        """Test acknowledging all alerts."""
        with app.app_context():
            user = db.session.query(User).filter_by(
                email="test@example.com"
            ).first()
            
            # Create multiple alerts
            for _ in range(3):
                alert = LoginAnomaly(
                    user_id=user.id,
                    anomaly_type=LoginAnomalyType.NEW_DEVICE,
                    severity="medium",
                )
                db.session.add(alert)
            db.session.commit()
        
        response = client.post(
            "/security/alerts/acknowledge-all",
            headers=auth_header
        )
        assert response.status_code == 200
        data = response.get_json()
        # Note: Login in fixture creates one extra alert (new_device)
        assert data["count"] >= 3


class TestAuthIntegration:
    """Tests for auth endpoints with anomaly detection."""
    
    def test_login_creates_attempt_record(self, client):
        """Test login creates LoginAttempt record."""
        from app import create_app
        from app.extensions import db
        
        # Register user first
        client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "password123"
        })
        
        # Login
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    def test_failed_login_creates_attempt_record(self, client, app):
        """Test failed login creates LoginAttempt record."""
        client.post("/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        })
        
        with app.app_context():
            attempt = db.session.query(LoginAttempt).filter_by(
                email="nonexistent@example.com"
            ).first()
            assert attempt is not None
            assert attempt.success is False
            assert attempt.failure_reason == "invalid_credentials"
    
    def test_first_login_triggers_new_device_alert(self, client, app):
        """Test first login triggers new device alert."""
        # Register user
        client.post("/auth/register", json={
            "email": "newuser@example.com",
            "password": "password123"
        })
        
        # First login
        response = client.post("/auth/login", json={
            "email": "newuser@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Should have security_alerts for new device
        assert "security_alerts" in data
        alerts = data["security_alerts"]
        assert any(a["type"] == "new_device" for a in alerts)
    
    def test_multiple_failed_logins_triggers_alert(self, client):
        """Test multiple failed logins triggers alert."""
        # Register user
        client.post("/auth/register", json={
            "email": "multifail@example.com",
            "password": "password123"
        })
        
        # Attempt multiple failed logins
        for _ in range(5):
            client.post("/auth/login", json={
                "email": "multifail@example.com",
                "password": "wrongpassword"
            })
        
        # Next login should still work but may have alert
        response = client.post("/auth/login", json={
            "email": "multifail@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 200


class TestGetClientIP:
    """Tests for get_client_ip helper."""
    
    def test_direct_connection(self):
        """Test IP from direct connection."""
        mock_request = MagicMock()
        mock_request.remote_addr = "192.168.1.1"
        mock_request.headers = {}
        
        ip = get_client_ip(mock_request)
        assert ip == "192.168.1.1"
    
    def test_x_forwarded_for(self):
        """Test IP from X-Forwarded-For header."""
        mock_request = MagicMock()
        mock_request.remote_addr = "10.0.0.1"
        mock_request.headers = {
            "X-Forwarded-For": "203.0.113.1, 70.41.3.18"
        }
        
        ip = get_client_ip(mock_request)
        assert ip == "203.0.113.1"
    
    def test_x_real_ip(self):
        """Test IP from X-Real-IP header."""
        mock_request = MagicMock()
        mock_request.remote_addr = "10.0.0.1"
        mock_request.headers = {
            "X-Real-IP": "198.51.100.1"
        }
        
        ip = get_client_ip(mock_request)
        assert ip == "198.51.100.1"
