import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.main import app  # noqa: E402


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_health(client):
    """Test que l'endpoint health marche"""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json['status'] == 'ok'
    assert response.json['service'] == 'api-gateway'


def test_app_runs(client):
    """Test que l'app Flask démarre correctement"""
    # Test d'une route qui n'existe pas
    response = client.get('/nonexistent')
    assert response.status_code == 404

    # Test que l'app répond bien
    response = client.get('/health')
    assert response.status_code == 200


def test_auth_service_unavailable(client):
    """Test que le proxy auth renvoie une erreur si le service est indispo."""
    response = client.post('/api/auth/login')
    assert response.status_code == 503
    assert response.json['error'] == 'Auth service unavailable'
