"""
run.py – Development entry-point.

Usage:
    python run.py
    SIMULATION=true python run.py
    INTERFACE=eth0 SIMULATION=false python run.py   # live capture (needs root)
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
