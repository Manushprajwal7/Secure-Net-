# config.py - Configuration file for Network Security Monitor

import os
from datetime import timedelta

class Config:
    # Security Settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-this-in-production')
    API_KEY = os.environ.get('API_KEY', 'your-api-key-change-this-in-production')
    
    # HTTPS Settings
    ENABLE_HTTPS = os.environ.get('ENABLE_HTTPS', 'False').lower() == 'true'
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', 'cert.pem')
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH', 'key.pem')
    
    # Network Interface - Update this with your actual interface
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', '\\Device\\NPF_{E3335482-8119-414C-BB72-78BA49EF185F}')
    
    # Security Thresholds
    PORT_SCAN_THRESHOLD = int(os.environ.get('PORT_SCAN_THRESHOLD', '20'))
    SYN_FLOOD_THRESHOLD = int(os.environ.get('SYN_FLOOD_THRESHOLD', '100'))
    SESSION_REPLAY_THRESHOLD = int(os.environ.get('SESSION_REPLAY_THRESHOLD', '1000'))
    
    # Time Windows
    SYN_FLOOD_WINDOW = timedelta(minutes=1)
    RATE_LIMIT_WINDOW = timedelta(minutes=5)
    BASELINE_LEARNING_PERIOD = timedelta(hours=1)
    
    # Packet Capture Settings
    MAX_PACKETS_IN_MEMORY = int(os.environ.get('MAX_PACKETS_IN_MEMORY', '100'))
    PACKET_CAPTURE_LIMIT = int(os.environ.get('PACKET_CAPTURE_LIMIT', '500'))
    
    # Alert Settings
    MAX_ALERTS_IN_MEMORY = int(os.environ.get('MAX_ALERTS_IN_MEMORY', '1000'))
    
    # Threat Intelligence
    ENABLE_THREAT_INTEL = os.environ.get('ENABLE_THREAT_INTEL', 'True').lower() == 'true'
    THREAT_INTEL_UPDATE_INTERVAL = timedelta(hours=6)
    
    # Notification Settings
    ENABLE_EMAIL_ALERTS = os.environ.get('ENABLE_EMAIL_ALERTS', 'False').lower() == 'true'
    EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
    EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', '587'))
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    EMAIL_RECIPIENTS = os.environ.get('EMAIL_RECIPIENTS', '').split(',')
    
    ENABLE_SLACK_ALERTS = os.environ.get('ENABLE_SLACK_ALERTS', 'False').lower() == 'true'
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
    
    # Firewall Integration
    ENABLE_AUTO_BLOCK = os.environ.get('ENABLE_AUTO_BLOCK', 'False').lower() == 'true'
    AUTO_BLOCK_SEVERITY_THRESHOLD = os.environ.get('AUTO_BLOCK_SEVERITY_THRESHOLD', 'HIGH')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'network_monitor.log')
    
    # Database (for persistent storage)
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///network_monitor.db')
    
    # Known Malicious IPs (can be updated from threat feeds)
    BLACKLISTED_IPS = [
        # Add known malicious IPs here
        # These would typically come from threat intelligence feeds
    ]
    
    # Trusted IPs (whitelist)
    TRUSTED_IPS = [
        # Add trusted IPs that should never be blocked
        '127.0.0.1',
        'localhost'
    ]
    
    # DNS Servers to monitor
    TRUSTED_DNS_SERVERS = [
        '8.8.8.8',      # Google DNS
        '8.8.4.4',      # Google DNS
        '1.1.1.1',      # Cloudflare DNS
        '1.0.0.1',      # Cloudflare DNS
    ]

class DevelopmentConfig(Config):
    DEBUG = True
    ENABLE_HTTPS = False

class ProductionConfig(Config):
    DEBUG = False
    ENABLE_HTTPS = True

class TestingConfig(Config):
    TESTING = True
    DEBUG = True

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}