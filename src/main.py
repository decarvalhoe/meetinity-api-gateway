from flask import Flask, jsonify, request
import requests

app = Flask(__name__)


@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "api-gateway"})


@app.route('/api/users/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_users(path):
    """Proxy vers le service utilisateur"""
    user_service_url = f"http://localhost:5001/{path}"
    try:
        response = requests.request(
            method=request.method,
            url=user_service_url,
            headers=request.headers,
            data=request.get_data(),
            params=request.args
        )
        return response.content, response.status_code
    except requests.exceptions.RequestException:
        return jsonify({"error": "User service unavailable"}), 503


@app.route('/api/events/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_events(path):
    """Proxy vers le service événements"""
    event_service_url = f"http://localhost:5003/{path}"
    try:
        response = requests.request(
            method=request.method,
            url=event_service_url,
            headers=request.headers,
            data=request.get_data(),
            params=request.args
        )
        return response.content, response.status_code
    except requests.exceptions.RequestException:
        return jsonify({"error": "Event service unavailable"}), 503


if __name__ == '__main__':
    app.run(debug=True, port=5000)
