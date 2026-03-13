import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", "network_scanner.db")

    # Port-scan detection: flag an IP that hits this many unique ports
    # within PORT_SCAN_WINDOW seconds.
    PORT_SCAN_THRESHOLD = int(os.environ.get("PORT_SCAN_THRESHOLD", "10"))
    PORT_SCAN_WINDOW = int(os.environ.get("PORT_SCAN_WINDOW", "10"))

    # High-frequency detection: flag an IP that sends this many packets
    # within HIGH_FREQ_WINDOW seconds.
    HIGH_FREQ_THRESHOLD = int(os.environ.get("HIGH_FREQ_THRESHOLD", "100"))
    HIGH_FREQ_WINDOW = int(os.environ.get("HIGH_FREQ_WINDOW", "5"))

    # Auto-block detected threats and release after BLOCK_DURATION seconds
    # (0 = permanent).
    AUTO_BLOCK = os.environ.get("AUTO_BLOCK", "true").lower() == "true"
    BLOCK_DURATION = int(os.environ.get("BLOCK_DURATION", "3600"))

    # Network interface for Scapy to listen on (None = default interface).
    INTERFACE = os.environ.get("INTERFACE", None)

    # Set SIMULATION=true to generate synthetic traffic instead of capturing
    # live packets (useful when Scapy cannot open a raw socket).
    SIMULATION = os.environ.get("SIMULATION", "true").lower() == "true"

    # How many packets per second the simulation injects.
    SIMULATION_RATE = float(os.environ.get("SIMULATION_RATE", "5"))
