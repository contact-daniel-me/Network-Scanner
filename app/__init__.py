"""
app/__init__.py – Flask application factory.
"""

import logging
import threading

from flask import Flask
from flask_cors import CORS

from app.database import init_db
from app import blocker  # noqa: F401  (re-exported for scanner.py)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Module-level analyzer instance shared across threads
# ---------------------------------------------------------------------------
_analyzer = None
_analyzer_lock = threading.Lock()


def get_analyzer():
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:
                from app.analyzer import TrafficAnalyzer
                _analyzer = TrafficAnalyzer()
    return _analyzer


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_app(config: dict | None = None):
    import os
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
    )

    app.config.from_object("config.Config")
    if config:
        app.config.update(config)

    CORS(app)
    init_db(app)

    from app.routes import bp
    app.register_blueprint(bp)

    # Re-initialise the analyzer with the final config thresholds.
    global _analyzer
    with _analyzer_lock:
        from app.analyzer import TrafficAnalyzer
        _analyzer = TrafficAnalyzer(
            port_scan_threshold=app.config["PORT_SCAN_THRESHOLD"],
            port_scan_window=app.config["PORT_SCAN_WINDOW"],
            high_freq_threshold=app.config["HIGH_FREQ_THRESHOLD"],
            high_freq_window=app.config["HIGH_FREQ_WINDOW"],
        )

    # Start the capture / simulation in a background daemon thread.
    if not app.config.get("TESTING"):
        from app import scanner
        t = threading.Thread(
            target=scanner.start_capture,
            args=(app,),
            daemon=True,
            name="PacketCapture",
        )
        t.start()

    return app
