import logging

from flask import Flask
from flask_cors import CORS

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
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.register_blueprint(scans_bp, url_prefix="/api")
    return app
