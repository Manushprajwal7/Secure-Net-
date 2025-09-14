# 🛡️ Network Security Monitor (IDS)
# Demo Video Link : https://youtu.be/29KEFXtrRrI

A comprehensive **Intrusion Detection System** with real-time network monitoring, threat analysis, and an advanced web dashboard for cybersecurity professionals.

![Network Security Monitor](https://img.shields.io/badge/Security-Network%20IDS-red?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-green?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## 🌟 Features

### 🔍 **Real-time Network Monitoring**
- **Live packet capture** and analysis using PyShark
- **Protocol detection** (TCP, UDP, ICMP, HTTP, HTTPS, DNS)
- **Network topology mapping** with interactive D3.js visualization
- **Traffic flow analysis** with real-time statistics

### 🚨 **Advanced Threat Detection**
- **Port scan detection** with configurable thresholds
- **SYN flood attack** identification
- **Brute force attack** monitoring
- **DNS tunneling** detection
- **Session replay attack** analysis
- **Threat intelligence** integration

### 🌐 **Interactive Network Map**
- **D3.js powered visualization** with drag-and-drop nodes
- **Device classification** (internal, external, gateway, server, workstation)
- **Real-time connection status** (normal, suspicious, blocked)
- **Advanced filtering** by device type, protocol, and IP
- **Security zones** visualization (Trusted, DMZ, External)

### ⚙️ **Comprehensive Settings Dashboard**
- **Security Rules** - Custom intrusion detection thresholds
- **Notifications** - Email, Slack, webhook, and browser alerts
- **Monitoring** - Performance thresholds and data retention
- **Network Configuration** - Interface and traffic analysis settings
- **Advanced Options** - API limits, database settings, system actions

### 📊 **Rich Analytics & Reporting**
- **Real-time charts** with Chart.js integration
- **Protocol distribution** analysis
- **Top destination ports** monitoring
- **Hourly traffic patterns**
- **Risk assessment** with security scoring
- **Alert trend analysis**

### 🔐 **Security Features**
- **API key authentication** for secure access
- **Auto-blocking** of malicious IPs
- **Firewall integration** for automated responses
- **Encrypted communications** with HTTPS support
- **Rate limiting** and DDoS protection

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+**
- **Wireshark/TShark** (for packet capture)
- **Administrator/Root privileges** (for network interface access)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Manushprajwal7/Secure-Net-
cd network-security-monitor
```

2. **Create virtual environment**
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure network interface**
```bash
# Find your network interface
python -c "import pyshark; print(pyshark.LiveCapture().interfaces)"
```
Update `NETWORK_INTERFACE` in `config.py` with your interface name.

5. **Run the application**
```bash
python app.py
```

6. **Access the dashboard**
Open your browser and navigate to `http://localhost:5000`

## 📁 Project Structure

```
network-security-monitor/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── notifications.py      # Alert notification system
├── threat_intel.py       # Threat intelligence module
├── test_packet_analysis.py # Testing utilities
├── templates/
│   └── index.html        # Main dashboard template
├── static/              # CSS, JS, and assets (if any)
├── .venv/              # Virtual environment
└── README.md           # This file
```

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# Security
SECRET_KEY=your-super-secret-key-change-this-in-production
API_KEY=your-api-key-change-this-in-production

# Network Interface (Update with your interface)
NETWORK_INTERFACE=\\Device\\NPF_{YOUR-INTERFACE-ID}

# Security Thresholds
PORT_SCAN_THRESHOLD=20
SYN_FLOOD_THRESHOLD=100

# HTTPS (Production)
ENABLE_HTTPS=false
SSL_CERT_PATH=cert.pem
SSL_KEY_PATH=key.pem

# Email Notifications
ENABLE_EMAIL_ALERTS=false
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_RECIPIENTS=admin@company.com,security@company.com

# Slack Notifications
ENABLE_SLACK_ALERTS=false
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Auto-blocking
ENABLE_AUTO_BLOCK=false
AUTO_BLOCK_SEVERITY_THRESHOLD=HIGH

# Database
DATABASE_URL=sqlite:///network_monitor.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=network_monitor.log
```

### Network Interface Setup

#### Windows
1. Install **Npcap** (comes with Wireshark)
2. Find interface ID:
```python
import pyshark
capture = pyshark.LiveCapture()
print(capture.interfaces)
```

#### Linux
```bash
# List interfaces
ip link show
# or
ifconfig -a

# Give permissions (if needed)
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python
```

#### macOS
```bash
# List interfaces
ifconfig -a

# Run with sudo (if needed)
sudo python app.py
```

## 🎯 Usage

### Dashboard Navigation
- **Overview** - Real-time statistics and network topology
- **Security Alerts** - Live threat notifications and analysis
- **Live Packets** - Real-time packet capture and inspection
- **Network Map** - Interactive network topology visualization
- **Settings** - System configuration and security rules

### API Endpoints
```bash
# Get network statistics
GET /network_stats
Headers: X-API-Key: your-api-key

# Get security alerts
GET /alerts
Headers: X-API-Key: your-api-key

# Block an IP address
POST /block_ip
Headers: X-API-Key: your-api-key, Content-Type: application/json
Body: {"ip": "192.168.1.100", "reason": "Malicious activity"}

# Get network topology
GET /network_topology
Headers: X-API-Key: your-api-key

# Real-time events (Server-Sent Events)
GET /events
Headers: X-API-Key: your-api-key
```

### Security Rules
Configure custom security rules in the Settings dashboard:
- **Port Scan Detection** - Set threshold for suspicious port scanning
- **SYN Flood Protection** - Configure packet rate limits
- **Brute Force Detection** - Set failed login attempt thresholds
- **Auto-blocking** - Automatically block malicious IPs
- **Custom IP Rules** - Block specific IP ranges
- **Port Access Control** - Restrict access to specific ports

## 🔧 Advanced Configuration

### Custom Threat Intelligence
Integrate with threat intelligence feeds by updating `threat_intel.py`:
```python
# Add custom threat feeds
THREAT_FEEDS = [
    'https://your-threat-feed.com/ips.txt',
    'https://another-feed.com/malicious-domains.json'
]
```

### Database Integration
For persistent storage, configure SQLAlchemy:
```python
# In config.py
DATABASE_URL = 'postgresql://user:password@localhost/network_monitor'
# or
DATABASE_URL = 'mysql://user:password@localhost/network_monitor'
```

### HTTPS Setup
For production deployment:
```bash
# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Update config
ENABLE_HTTPS=true
SSL_CERT_PATH=cert.pem
SSL_KEY_PATH=key.pem
```

## 🧪 Testing

Run the test suite:
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest test_packet_analysis.py -v

# Run with coverage
pytest --cov=app test_packet_analysis.py
```

## 📊 Monitoring & Logging

### Log Files
- **network_monitor.log** - Application logs
- **packet_capture.log** - Packet analysis logs
- **security_alerts.log** - Security event logs

### Performance Monitoring
Monitor system resources through the dashboard:
- CPU usage alerts
- Memory usage monitoring
- Disk space tracking
- Network interface statistics

## 🚨 Security Considerations

### Production Deployment
1. **Change default keys** - Update SECRET_KEY and API_KEY
2. **Enable HTTPS** - Use SSL certificates for encrypted communication
3. **Firewall rules** - Restrict access to monitoring ports
4. **Regular updates** - Keep dependencies updated
5. **Log monitoring** - Monitor logs for suspicious activities
6. **Backup strategy** - Regular backups of configuration and data

### Network Permissions
- Requires **administrator/root privileges** for packet capture
- Consider running in a **dedicated security VLAN**
- Implement **network segmentation** for isolation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🆘 Support & Troubleshooting

### Common Issues

**Issue**: Permission denied for packet capture
```bash
# Linux/Mac: Run with sudo or set capabilities
sudo python app.py
# or
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
```

**Issue**: Network interface not found
```python
# List available interfaces
import pyshark
print(pyshark.LiveCapture().interfaces)
# Update NETWORK_INTERFACE in config.py
```

**Issue**: High CPU usage
- Reduce `PACKET_CAPTURE_LIMIT` in config.py
- Increase `SYN_FLOOD_WINDOW` for less frequent analysis
- Enable packet filtering for specific protocols only

### Performance Optimization
- **Packet Filtering** - Capture only relevant traffic
- **Memory Management** - Adjust `MAX_PACKETS_IN_MEMORY`
- **Database Optimization** - Use PostgreSQL for better performance
- **Caching** - Implement Redis for session management

## 📞 Contact

- **Author**: Manush Prajwal
- **Email**: manushprajwal555@gmail.com
- **Project Link**: https://github.com/Manushprajwal7/Secure-Net-

## 🙏 Acknowledgments

- **PyShark** - Python packet analysis library
- **Flask** - Lightweight web framework
- **D3.js** - Data visualization library
- **Chart.js** - Beautiful charts and graphs
- **Bootstrap** - Responsive UI framework
- **Font Awesome** - Icon library

---

⭐ **Star this repository if you find it helpful!** ⭐

![Network Security](https://img.shields.io/badge/Stay-Secure-brightgreen?style=for-the-badge&logo=security)
