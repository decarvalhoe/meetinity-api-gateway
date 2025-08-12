import os
import requests
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

limiter = Limiter(key_func=get_remote_address)


def create_app():
    load_dotenv()
    app = Flask(__name__)

    # Config
    app.config["USER_SERVICE_URL"] = os.getenv("USER_SERVICE_URL", "")
    app.config["JWT_SECRET"] = os.getenv("JWT_SECRET", "")
    app.config["RATE_LIMIT_AUTH"] = os.getenv("RATE_LIMIT_AUTH", "10/minute")

    # CORS
    origins_env = os.getenv("CORS_ORIGINS", "")
    origins = [o.strip() for o in origins_env.split(",") if o.strip()]
    CORS(app, origins=origins)

    # Limiter
    limiter.init_app(app)

    from .routes.proxy import proxy_bp
    app.register_blueprint(proxy_bp)

    @app.route("/health")
    def health():
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
        return jsonify({"error": "Too Many Requests"}), 429

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(port=int(os.getenv("APP_PORT", 5000)))
