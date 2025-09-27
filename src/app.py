"""Meetinity API Gateway.

This module provides the main application factory for the API Gateway,
which serves as the central entry point for all client requests to the
Meetinity microservices architecture.
"""

import os
import requests
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

limiter = Limiter(key_func=get_remote_address)


def create_app():
    """Create and configure the Flask application.
    
    Returns:
        Flask: The configured Flask application instance.
    """
    load_dotenv()
    app = Flask(__name__)

    # Configuration from environment variables
    app.config["USER_SERVICE_URL"] = os.getenv("USER_SERVICE_URL", "")
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
    app.config["RATE_LIMIT_AUTH"] = os.getenv("RATE_LIMIT_AUTH", "10/minute")

    # CORS configuration
    origins_env = os.getenv("CORS_ORIGINS", "")
    origins = [o.strip() for o in origins_env.split(",") if o.strip()]
    CORS(app, origins=origins)

    # Rate limiter initialization
    limiter.init_app(app)

    # Register blueprints
    from .routes.proxy import proxy_bp
    app.register_blueprint(proxy_bp)

    @app.route("/health")
    def health():
        """Health check endpoint for the API Gateway.
        
        This endpoint checks the health of the gateway itself and
        the connectivity to upstream services.
        
        Returns:
            Response: JSON response with health status of gateway and upstream services.
        """
        status = "down"
        url = app.config["USER_SERVICE_URL"].rstrip("/")
        if url:
            try:
                resp = requests.get(f"{url}/health", timeout=5)
                if resp.status_code == 200:
                    status = "up"
            except requests.RequestException:
                pass
        return jsonify({
            "status": "ok",
            "service": "api-gateway",
            "upstreams": {"user_service": status},
        })

    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Handle rate limit exceeded errors.
        
        Args:
            e: The rate limit error object.
            
        Returns:
            Response: JSON error response with 429 status code.
        """
        return jsonify({"error": "Too Many Requests"}), 429

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(port=int(os.getenv("APP_PORT", 5000)))
