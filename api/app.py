import logging

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from api.routes import bp as scans_bp
from config import settings
from engine.agent_runtime.tracing import configure_runtime_observability


def create_app() -> Flask:
    configure_runtime_observability()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = int(settings.max_upload_bytes)
    origins = [o.strip() for o in settings.api_cors_origins.split(",") if o.strip()] or None
    CORS(app, resources={r"/api/*": {"origins": origins}})
    app.register_blueprint(scans_bp, url_prefix="/api")

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_e):
        limit = int(settings.max_upload_bytes)
        return jsonify({"error": f"upload exceeds the {limit} byte limit"}), 413

    return app
