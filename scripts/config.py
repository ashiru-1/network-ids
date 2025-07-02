"""
Configuration settings for the Network IDS
"""

# File paths
SIGNATURE_FILE = "signatures.json"
ALERT_FILE = "alerts.json"
EVALUATION_FILE = "evaluation_results.json"

# Detection settings
DEFAULT_SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
MAX_PAYLOAD_LENGTH = 1000  # Maximum payload length to analyze
ALERT_THRESHOLD = 1  # Minimum number of signature matches to generate alert

# Performance settings
BATCH_SIZE = 1000  # Number of packets to process in each batch
PROGRESS_INTERVAL = 100  # Show progress every N packets

# Simulation settings
DEFAULT_SIMULATION_PACKETS = 1000
MALICIOUS_TRAFFIC_RATIO = 0.1  # 10% of simulated traffic is malicious

# Network settings
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
SAMPLE_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5", "10.0.0.10", "10.0.0.15",
    "172.16.0.100", "172.16.0.200",
    "8.8.8.8", "1.1.1.1"
]

# Logging settings
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Report settings
MAX_DETAILED_ALERTS = 10
MAX_ERROR_EXAMPLES = 5
