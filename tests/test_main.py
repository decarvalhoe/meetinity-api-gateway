import pytest
from src.main import app


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
