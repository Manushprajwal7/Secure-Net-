# Enhanced Network Security Monitor

## Overview

This enhanced network security monitor provides comprehensive MITM detection, intrusion detection, and network monitoring capabilities with real-time alerts and automated response features.

## Features Implemented

### 🔐 Network Security Enhancements
- **ARP Spoofing Detection**: Monitors ARP replies and detects multiple MACs claiming the same IP
- **Gateway Monitoring**: Tracks default gateway MAC address changes
- **DNS Spoofing Detection**: Monitors DNS responses for suspicious domain-to-IP mappings
- **SSL/TLS Certificate Validation**: Basic certificate fingerprint monitoring
- **Threat Intelligence Integration**: Real-time blacklist checking against malicious IPs

### 🛡️ Intrusion Detection Features
- **Port Scan Detection**: Identifies rapid port scanning attempts
- **SYN Flood Detection**: Monitors for SYN flood attacks
- **Session Hijack Monitoring**: Detects duplicate TCP sessions
- **Rate Limiting**: Tracks connection rates and identifies anomalies
- **Packet Anomaly Detection**: Flags unusual protocols and malformed packets

### 🔍 Data Integrity & Safety
- **Unencrypted Traffic Detection**: Warns about HTTP vs HTTPS usage
- **Credential Exposure Detection**: Basic plaintext credential detection
- **Protocol Security Monitoring**: Identifies use of insecure protocols (Telnet, FTP, etc.)

### 🔧 Security Hardening
- **API Authentication**: JWT/API key protection for all endpoints
- **HTTPS Support**: TLS encryption for Flask API
- **Secure Reporting**: Encrypted communication with signature verification
- **Rate Limiting**: Protection against API abuse

### 📊 Monitoring & Alerts
- **Real-time Dashboard**: Modern web interface with live updates
- **Multi-channel Notifications**: Email, Slack, Discord, SMS, webhooks
- **Threat Intelligence**: Automated blacklist updates from external feeds
- **Network Baseline**: Learn normal network behavior and detect anomalies

## Requirements

### Python Dependencies

```
# Core Dependencies
flask==2.3.3
flask-cors==4.0.0
pyshark==0.6
requests==2.31.0
dnspython==2.4.2

# Security & Encryption
cryptography==41.0.7
pyjwt==2.8.0

# Database (Optional)
sqlalchemy==2.0.23
flask-sqlalchemy==3.1.1

# Notifications
twilio==8.9.1  # For SMS notifications (optional)

# Development & Testing
pytest==7.4.3
pytest-cov==4.1.0
```

### System Dependencies

#### Windows
- **WinPcap** or **Npcap**: Required for packet capture
- **Python 3.8+**: Required for all features
- **PowerShell**: For network interface discovery

#### Linux
- **libpcap-dev**: Packet capture library
- **python3-dev**: Python development headers
- **iptables**: For automated IP blocking

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev python3-dev python3-pip

# CentOS/RHEL
sudo yum install libpcap-devel python3-devel python3-pip
```

#### macOS
```bash
# Install via Homebrew
brew install libpcap python3

# Install Python dependencies
pip3 install -r requirements.txt
```

## Installation & Setup

### 1. Clone and Install

```bash
# Clone the repository
git clone <repository-url>
cd network-security-monitor

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Network Interface Configuration

#### Find Your Network Interface

**Windows:**
```cmd
# List available interfaces
netsh interface show interface

# Find Npcap interfaces
python -c "import pyshark; print(pyshark.LiveCapture().interfaces)"
```

**Linux:**
```bash
# List interfaces
ip link show
# or
ifconfig -a
```

Update the `NETWORK_INTERFACE` in `config.py` with your actual interface name.

### 3. Security Configuration

Create a `.env` file in the project root:

```env
# Security Keys (CHANGE THESE!)
SECRET_KEY=your-super-secret-key-change-this-in-production
API_KEY=your-api-key-change-this-in-production

# HTTPS Configuration
ENABLE_HTTPS=False
SSL_CERT_PATH=cert.pem
SSL_KEY_PATH=key.pem

# Network Interface
NETWORK_INTERFACE=\\Device\\NPF_{YOUR-INTERFACE-ID}

# Threat Intelligence
ENABLE_THREAT_INTEL=True

# Email Notifications
ENABLE_EMAIL_ALERTS=False
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_RECIPIENTS=admin@company.com,security@company.com

# Slack Notifications
ENABLE_SLACK_ALERTS=False
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Auto-blocking
ENABLE_AUTO_BLOCK=False
AUTO_BLOCK_SEVERITY_THRESHOLD=HIGH
```

### 4. Generate SSL Certificates (for HTTPS)

```bash
# Generate self-signed certificate for development
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 5. Database Setup (Optional)

```python
# Initialize database
from app import db
db.create_all()
```

## Running the Application

### Development Mode

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Set environment
export FLASK_ENV=development  # Linux/macOS
# or
set FLASK_ENV=development     # Windows

# Run the application
python enhanced_network_monitor.py
```

### Production Mode

```bash
# Set production environment
export FLASK_ENV=production
export ENABLE_HTTPS=True

# Run with production settings
python enhanced_network_monitor.py
```

### Running as a Service

#### Windows Service

```cmd
# Install as Windows service using NSSM
nssm install NetworkSecurityMonitor
nssm set NetworkSecurityMonitor Application python.exe
nssm set NetworkSecurityMonitor AppParameters enhanced_network_monitor.py
nssm set NetworkSecurityMonitor AppDirectory C:\path\to\your\project
nssm start NetworkSecurityMonitor
```

#### Linux Systemd Service

Create `/etc/systemd/system/network-security-monitor.service`:

```ini
[Unit]
Description=Network Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/your/project
Environment=PATH=/path/to/your/venv/bin
ExecStart=/path/to/your/venv/bin/python enhanced_network_monitor.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable network-security-monitor
sudo systemctl start network-security-monitor
```

## Usage

### Web Dashboard

1. Open your browser and navigate to:
   - HTTP: `http://localhost:5000`
   - HTTPS: `https://localhost:5000`

2. Use the API key in requests:
   ```bash
   curl -H "X-API-Key: your-api-key-here" http://localhost:5000/alerts
   ```

### API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/` | GET | Dashboard | No |
| `/data` | GET | Get captured packets | Yes |
| `/alerts` | GET | Get security alerts | Yes |
| `/network_stats` | GET | Get network statistics | Yes |
| `/block_ip` | POST | Block an IP address | Yes |
| `/events` | GET | Server-sent events stream | No |

### Configuration Files

- `config.py`: Main configuration settings
- `.env`: Environment variables and secrets
- `requirements.txt`: Python dependencies

## Customization

### Adding Custom Threat Intelligence Feeds

```python
# In threat_intel.py
ti_manager = ThreatIntelligenceManager()

# Add custom feed
custom_feed = {
    'name': 'Custom Threat Feed',
    'type': 'ip',
    'url': 'https://your-threat-feed.com/ips.txt',
    'enabled': True
}
ti_manager.feeds.append(custom_feed)
```

### Custom Alert Rules

```python
# In the SecurityMonitor class
def check_custom_rule(self, packet):
    # Implement your custom detection logic
    if your_condition:
        self.add_alert(
            "CUSTOM_RULE",
            "HIGH",
            "Custom rule triggered",
            source_ip=packet.ip.src
        )
```

### Adding Notification Channels

```python
# Email
email_channel = create_email_channel(
    name="security_team",
    smtp_server="smtp.company.com",
    smtp_port=587,
    from_email="security@company.com",
    to_emails=["admin@company.com"]
)

# Slack
slack_channel = create_slack_channel(
    name="security_alerts",
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK"
)

notifier.add_channel(email_channel)
notifier.add_channel(slack_channel)
```

## Troubleshooting

### Common Issues

1. **Permission Errors**: Run as administrator/root for packet capture
2. **Interface Not Found**: Update `NETWORK_INTERFACE` in config
3. **SSL Errors**: Generate proper certificates or disable HTTPS
4. **Rate Limiting**: Adjust thresholds in configuration

### Debug Mode

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Run with debug mode
python enhanced_network_monitor.py --debug
```

### Log Files

- Application logs: `network_monitor.log`
- Security alerts: `security_alerts.log`
- System logs: Check system event logs

## Security Considerations

### Production Deployment

1. **Change Default Keys**: Update `SECRET_KEY` and `API_KEY`
2. **Enable HTTPS**: Use proper SSL certificates
3. **Firewall Rules**: Restrict access to monitoring ports
4. **Regular Updates**: Keep dependencies updated
5. **Access Control**: Implement proper authentication
6. **Log Monitoring**: Monitor application logs
7. **Backup Strategy**: Regular backups of configuration and logs

### Network Security

1. **Isolated Network**: Run on dedicated monitoring network
2. **VPN Access**: Secure remote access to dashboard
3. **Certificate Validation**: Use proper CA-signed certificates
4. **API Rate Limiting**: Configure appropriate rate limits

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## License

[Your License Here]

## Support

For support and questions:
- Documentation: [Link to docs]
- Issues: [GitHub Issues]
- Email: security@company.com
