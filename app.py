from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS
import json
import pyshark
import threading
import time
import base64
import ipaddress
import requests
import socket
from datetime import datetime, timedelta
import hashlib
import hmac
import ssl
import dns.resolver
import dns.exception
from collections import defaultdict, deque
import re
import subprocess
import platform
import os
import logging
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_monitor.log')
    ]
)
logger = logging.getLogger(__name__)

# Set debug level for development
if os.environ.get('DEBUG', 'False').lower() == 'true':
    logger.setLevel(logging.DEBUG)

app = Flask(__name__, template_folder='templates')
CORS(app)

# Security Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
API_KEY = os.environ.get('API_KEY', 'your-api-key-here')
ENABLE_HTTPS = os.environ.get('ENABLE_HTTPS', 'False').lower() == 'true'

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)

app.json_encoder = CustomJSONEncoder

class SecurityAlert:
    def __init__(self, alert_type, severity, message, source_ip="", target_ip="", timestamp=None):
        self.alert_type = alert_type
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.message = message
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.timestamp = timestamp or datetime.now()
        self.id = hashlib.md5(f"{alert_type}{message}{timestamp}".encode()).hexdigest()[:8]

class NetworkBaseline:
    def __init__(self):
        self.known_devices = {}  # MAC -> {IP, first_seen, last_seen, hostname}
        self.normal_services = defaultdict(set)  # IP -> set of ports
        self.dns_mappings = {}  # domain -> set of IPs
        self.gateway_mac = None
        self.gateway_ip = None
        self.baseline_established = False
        self.learning_period = timedelta(hours=1)  # Learn for 1 hour
        self.start_time = datetime.now()

class SecurityMonitor:
    def __init__(self):
        self.alerts = deque(maxlen=1000)
        self.baseline = NetworkBaseline()
        self.arp_table = {}  # IP -> MAC
        self.dns_cache = {}  # domain -> IP
        self.connection_tracker = defaultdict(lambda: defaultdict(int))  # src_ip -> dst_port -> count
        self.syn_tracker = defaultdict(list)  # IP -> timestamps of SYN packets
        self.session_tracker = {}  # (src_ip, dst_ip, src_port, dst_port) -> count
        self.blacklisted_ips = set()
        self.threat_indicators = set()
        
        # Rate limiting counters
        self.rate_limits = defaultdict(lambda: defaultdict(list))  # IP -> protocol -> timestamps
        
        # Load threat intelligence
        self.load_threat_intelligence()
        
        # Discover gateway
        self.discover_gateway()

        # Severity ranking for auto-block logic
        self.severity_rank = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4,
        }

    def load_threat_intelligence(self):
        """Load known malicious IPs and domains"""
        # This would typically load from external threat feeds
        # For demo purposes, adding some example IPs
        malicious_ips = [
            "192.168.1.666",  # Obviously fake for demo
            "10.0.0.666",
        ]
        self.blacklisted_ips.update(malicious_ips)

    def discover_gateway(self):
        """Discover the default gateway"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                      capture_output=True, text=True)
                # Parse Windows route output to find gateway
                for line in result.stdout.split('\n'):
                    if '0.0.0.0' in line and 'Gateway' not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            self.baseline.gateway_ip = parts[2]
                            break
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True)
                if result.stdout:
                    parts = result.stdout.strip().split()
                    if len(parts) >= 3:
                        self.baseline.gateway_ip = parts[2]
            
            logger.info(f"Discovered gateway IP: {self.baseline.gateway_ip}")
        except Exception as e:
            logger.error(f"Failed to discover gateway: {e}")

    def add_alert(self, alert_type, severity, message, source_ip="", target_ip=""):
        """Add a security alert"""
        alert = SecurityAlert(alert_type, severity, message, source_ip, target_ip)
        self.alerts.append(alert)
        logger.warning(f"SECURITY ALERT [{severity}]: {message}")
        
        # Send real-time notification
        self.send_realtime_alert(alert)
        
        # Optional auto-blocking based on settings
        try:
            if app_settings.get('auto_block', False):
                threshold = app_settings.get('auto_block_severity_threshold', 'HIGH')
                if self.severity_rank.get(severity, 0) >= self.severity_rank.get(threshold, 3):
                    ip_to_block = source_ip or target_ip
                    if ip_to_block:
                        # Avoid blocking localhost
                        if ip_to_block not in ['127.0.0.1', 'localhost']:
                            block_ip_system(ip_to_block)
                            self.blacklisted_ips.add(ip_to_block)
                            logger.info(f"Auto-blocked IP due to {severity} alert: {ip_to_block}")
        except Exception as e:
            logger.error(f"Auto-block failed: {e}")
        
        return alert

    def send_realtime_alert(self, alert):
        """Send real-time alert via webhook or email"""
        # This would integrate with Slack, Discord, email, etc.
        logger.info(f"Real-time alert sent: {alert.message}")

    def check_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        try:
            if hasattr(packet, 'arp') and packet.arp:
                if hasattr(packet.arp, 'opcode') and packet.arp.opcode == '2':  # ARP Reply
                    if hasattr(packet.arp, 'psrc_resolved') and hasattr(packet.arp, 'hwsrc'):
                        ip = packet.arp.psrc_resolved
                        mac = packet.arp.hwsrc
                        
                        if ip and mac:
                            if ip in self.arp_table:
                                if self.arp_table[ip] != mac:
                                    self.add_alert(
                                        "ARP_SPOOFING",
                                        "HIGH",
                                        f"ARP spoofing detected! IP {ip} claimed by multiple MACs: {self.arp_table[ip]} and {mac}",
                                        source_ip=ip
                                    )
                            else:
                                self.arp_table[ip] = mac
                            
                            # Check if gateway MAC changed
                            if self.baseline.gateway_ip and ip == self.baseline.gateway_ip:
                                if self.baseline.gateway_mac and self.baseline.gateway_mac != mac:
                                    self.add_alert(
                                        "GATEWAY_MAC_CHANGE",
                                        "CRITICAL",
                                        f"Gateway MAC address changed from {self.baseline.gateway_mac} to {mac}! Possible MITM attack",
                                        source_ip=ip
                                    )
                                else:
                                    self.baseline.gateway_mac = mac
        except Exception as e:
            logger.debug(f"ARP spoofing check failed: {e}")

    def check_dns_spoofing(self, packet):
        """Detect DNS spoofing"""
        try:
            if hasattr(packet, 'dns') and packet.dns and hasattr(packet.dns, 'qry_name'):
                domain = packet.dns.qry_name
                if domain and hasattr(packet.dns, 'a'):
                    ip = packet.dns.a
                    
                    if ip:
                        if domain in self.dns_cache:
                            if self.dns_cache[domain] != ip:
                                self.add_alert(
                                    "DNS_SPOOFING",
                                    "HIGH",
                                    f"DNS spoofing detected! Domain {domain} resolved to different IPs: {self.dns_cache[domain]} and {ip}",
                                    target_ip=ip
                                )
                        else:
                            self.dns_cache[domain] = ip
        except Exception as e:
            logger.debug(f"DNS spoofing check failed: {e}")

    def check_port_scan(self, packet):
        """Detect port scanning attempts"""
        try:
            if hasattr(packet, 'tcp') and packet.tcp and hasattr(packet, 'ip') and packet.ip:
                if hasattr(packet.tcp, 'dstport') and hasattr(packet.ip, 'src'):
                    src_ip = packet.ip.src
                    dst_port = packet.tcp.dstport
                    
                    if src_ip and dst_port:
                        # Track connection attempts
                        self.connection_tracker[src_ip][dst_port] += 1
                        
                        # Check if too many different ports accessed from same IP
                        threshold = app_settings.get('port_scan_threshold', 20)
                        if len(self.connection_tracker[src_ip]) > threshold:
                            self.add_alert(
                                "PORT_SCAN",
                                "MEDIUM",
                                f"Port scan detected from {src_ip}. Accessed {len(self.connection_tracker[src_ip])} different ports",
                                source_ip=src_ip
                            )
                            # Reset counter to avoid spam
                            self.connection_tracker[src_ip].clear()
        except Exception as e:
            logger.debug(f"Port scan check failed: {e}")

    def check_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        try:
            if hasattr(packet, 'tcp') and packet.tcp and hasattr(packet, 'ip') and packet.ip:
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                    if hasattr(packet.ip, 'src'):
                        src_ip = packet.ip.src
                        if src_ip:
                            current_time = datetime.now()
                            
                            # Track SYN packets
                            self.syn_tracker[src_ip].append(current_time)
                            
                            # Remove old entries (older than 1 minute)
                            self.syn_tracker[src_ip] = [
                                t for t in self.syn_tracker[src_ip] 
                                if current_time - t < timedelta(minutes=1)
                            ]
                            
                            # Check if too many SYNs in short time
                            threshold = app_settings.get('syn_flood_threshold', 100)
                            if len(self.syn_tracker[src_ip]) > threshold:
                                self.add_alert(
                                    "SYN_FLOOD",
                                    "HIGH",
                                    f"SYN flood detected from {src_ip}. {len(self.syn_tracker[src_ip])} SYN packets in last minute",
                                    source_ip=src_ip
                                )
        except Exception as e:
            logger.debug(f"SYN flood check failed: {e}")

    def check_session_hijack(self, packet):
        """Detect potential session hijacking"""
        try:
            if hasattr(packet, 'tcp') and packet.tcp and hasattr(packet, 'ip') and packet.ip:
                if (hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst') and 
                    hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport')):
                    
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    
                    if src_ip and dst_ip and src_port and dst_port:
                        session_key = (src_ip, dst_ip, src_port, dst_port)
                        
                        if session_key in self.session_tracker:
                            self.session_tracker[session_key] += 1
                            
                            # Alert if same session appears too frequently (possible replay)
                            threshold = app_settings.get('session_replay_threshold', 1000)
                            if self.session_tracker[session_key] > threshold:
                                self.add_alert(
                                    "SESSION_HIJACK",
                                    "HIGH",
                                    f"Potential session hijacking detected. Duplicate session: {session_key}",
                                    source_ip=src_ip,
                                    target_ip=dst_ip
                                )
                        else:
                            self.session_tracker[session_key] = 1
        except Exception as e:
            logger.debug(f"Session hijack check failed: {e}")

    def check_threat_intelligence(self, packet):
        """Check against threat intelligence feeds"""
        try:
            if hasattr(packet, 'ip') and packet.ip:
                if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    if src_ip and src_ip in self.blacklisted_ips:
                        self.add_alert(
                            "MALICIOUS_IP",
                            "CRITICAL",
                            f"Connection from known malicious IP: {src_ip}",
                            source_ip=src_ip
                        )
                    
                    if dst_ip and dst_ip in self.blacklisted_ips:
                        self.add_alert(
                            "MALICIOUS_IP",
                            "CRITICAL",
                            f"Connection to known malicious IP: {dst_ip}",
                            target_ip=dst_ip
                        )
        except Exception as e:
            logger.debug(f"Threat intelligence check failed: {e}")

    def check_unencrypted_traffic(self, packet):
        """Check for sensitive data over unencrypted connections"""
        try:
            if hasattr(packet, 'tcp') and packet.tcp and hasattr(packet, 'ip') and packet.ip:
                if hasattr(packet.tcp, 'dstport') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
                    # Check for HTTP traffic (should be HTTPS)
                    if packet.tcp.dstport == '80':
                        self.add_alert(
                            "UNENCRYPTED_HTTP",
                            "MEDIUM",
                            f"HTTP traffic detected from {packet.ip.src} to {packet.ip.dst}. Consider using HTTPS",
                            source_ip=packet.ip.src,
                            target_ip=packet.ip.dst
                        )
                    
                    # Check for other unencrypted protocols
                    try:
                        port = int(packet.tcp.dstport)
                        if port in [21, 23, 25, 110]:  # FTP, Telnet, SMTP, POP3
                            protocol_map = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 110: 'POP3'}
                            self.add_alert(
                                "UNENCRYPTED_PROTOCOL",
                                "MEDIUM",
                                f"Unencrypted {protocol_map[port]} traffic detected",
                                source_ip=packet.ip.src,
                                target_ip=packet.ip.dst
                            )
                    except (ValueError, TypeError):
                        pass  # Invalid port number
        except Exception as e:
            logger.debug(f"Unencrypted traffic check failed: {e}")

    def analyze_packet(self, packet):
        """Comprehensive packet analysis"""
        try:
            # Basic packet validation
            if not packet:
                return
                
            # Run all security checks
            self.check_arp_spoofing(packet)
            self.check_dns_spoofing(packet)
            self.check_port_scan(packet)
            self.check_syn_flood(packet)
            self.check_session_hijack(packet)
            self.check_threat_intelligence(packet)
            self.check_unencrypted_traffic(packet)
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
            # Log packet info for debugging
            try:
                if hasattr(packet, 'highest_layer'):
                    logger.debug(f"Packet layer: {packet.highest_layer}")
                if hasattr(packet, 'sniff_time'):
                    logger.debug(f"Packet time: {packet.sniff_time}")
            except:
                pass

class Packets:
    def __init__(self, ipsrc="", time_stamp='', srcport='', transport_layer='', dstnport='', highest_layer='', ipdst=''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstnport = dstnport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer

class apiServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

# Security decorator for API authentication
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        provided_key = request.headers.get('X-API-Key')
        if not provided_key or not hmac.compare_digest(provided_key, API_KEY):
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Initialize security monitor
security_monitor = SecurityMonitor()

# Automatically get local machine IP
local_ip = socket.gethostbyname(socket.gethostname())
server = apiServer(local_ip, '3000')

# Set correct network interface (Replace with your valid one)
network_interface = "\\Device\\NPF_{E3335482-8119-414C-BB72-78BA49EF185F}"  # Wi-Fi
capture = pyshark.LiveCapture(interface=network_interface)

# Runtime-updatable settings
app_settings = {
    'port_scan_threshold': 20,
    'syn_flood_threshold': 100,
    'session_replay_threshold': 1000,
    'auto_block': False,
    'auto_block_severity_threshold': 'HIGH',
}

def block_ip_system(ip_to_block: str):
    try:
        if platform.system() == "Windows":
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=BlockMaliciousIP', 'dir=in', 'action=block',
                f'remoteip={ip_to_block}'
            ])
        else:
            subprocess.run([
                'iptables', '-A', 'INPUT', '-s', ip_to_block, '-j', 'DROP'
            ])
    except Exception as e:
        logger.error(f"System block command failed for {ip_to_block}: {e}")

def check_if_api_server(packet, server):
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        if packet.ip.src == server.ip or packet.ip.dst == server.ip:
            return True
    return False

def check_if_private_ipadress(ip_addr):
    try:
        ip = ipaddress.ip_address(ip_addr)
        return ip.is_private
    except:
        return False

def secure_report(message):
    """Secure reporting mechanism using POST with encryption"""
    try:
        # Create a serializable version of the message
        serializable_data = {}
        for key, value in message.__dict__.items():
            if isinstance(value, datetime):
                serializable_data[key] = value.isoformat()
            else:
                serializable_data[key] = value
        
        # Create secure payload
        payload = {
            'data': serializable_data,
            'timestamp': datetime.now().isoformat(),
            'signature': hmac.new(
                SECRET_KEY.encode(),
                json.dumps(serializable_data, default=str).encode(),
                hashlib.sha256
            ).hexdigest()
        }
        
        # Use POST instead of GET for security
        response = requests.post(
            f'http://{server.ip}:{server.port}/api/report',
            json=payload,
            timeout=5
        )
        
    except requests.ConnectionError:
        pass
    except Exception as e:
        logger.error(f"Error in secure reporting: {e}")

def check_packet_filter(packet):
    """Filter and analyze packets for security threats"""
    try:
        if not packet:
            return
            
        # Run security analysis first
        security_monitor.analyze_packet(packet)
        
        if check_if_api_server(packet, server):
            return
            
        if hasattr(packet, 'icmp'):
            try:
                DataGram = Packets()
                if hasattr(packet, 'ip') and packet.ip:
                    if hasattr(packet.ip, 'dst') and hasattr(packet.ip, 'src'):
                        DataGram.ipdst = packet.ip.dst
                        DataGram.ipsrc = packet.ip.src
                DataGram.highest_layer = getattr(packet, 'highest_layer', 'Unknown')
                DataGram.time_stamp = getattr(packet, 'sniff_time', datetime.now())
                secure_report(DataGram)
            except Exception as e:
                logger.debug(f"ICMP packet processing failed: {e}")
                
        if hasattr(packet, 'transport_layer') and packet.transport_layer in ['TCP', 'UDP']:
            try:
                DataGram = Packets()
                if hasattr(packet, 'ipv6'):
                    return
                if hasattr(packet, 'ip') and packet.ip:
                    if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        if check_if_private_ipadress(src_ip) and check_if_private_ipadress(dst_ip):
                            DataGram.ipsrc = src_ip
                            DataGram.ipdst = dst_ip
                            DataGram.time_stamp = getattr(packet, 'sniff_time', datetime.now())
                            DataGram.highest_layer = getattr(packet, 'highest_layer', 'Unknown')
                            DataGram.transport_layer = packet.transport_layer
                            
                            if packet.transport_layer == 'UDP' and hasattr(packet, 'udp'):
                                if hasattr(packet.udp, 'dstport') and hasattr(packet.udp, 'srcport'):
                                    DataGram.dstnport = packet.udp.dstport
                                    DataGram.srcport = packet.udp.srcport
                            elif packet.transport_layer == 'TCP' and hasattr(packet, 'tcp'):
                                if hasattr(packet.tcp, 'dstport') and hasattr(packet.tcp, 'srcport'):
                                    DataGram.dstnport = packet.tcp.dstport
                                    DataGram.srcport = packet.tcp.srcport
                                    
                            secure_report(DataGram)
            except Exception as e:
                logger.debug(f"Transport layer packet processing failed: {e}")
                
    except Exception as e:
        logger.error(f"Packet filter error: {e}")
        # Continue processing other packets

def serialize_packet(packet):
    """Safely serialize packet data for JSON transmission"""
    try:
        if not packet:
            return {
                'time_stamp': '',
                'ipsrc': '',
                'ipdst': '',
                'srcport': '',
                'dstnport': '',
                'transport_layer': '',
                'highest_layer': '',
            }
            
        # Safely get transport layer info
        transport_layer = getattr(packet, 'transport_layer', None)
        srcport = ''
        dstport = ''
        
        if transport_layer and hasattr(packet, transport_layer):
            try:
                transport_obj = getattr(packet, transport_layer)
                if hasattr(transport_obj, 'srcport'):
                    srcport = str(transport_obj.srcport)
                if hasattr(transport_obj, 'dstport'):
                    dstport = str(transport_obj.dstport)
            except Exception as e:
                logger.debug(f"Transport layer serialization failed: {e}")
        
        # Safely get IP info
        ipsrc = ''
        ipdst = ''
        if hasattr(packet, 'ip') and packet.ip:
            try:
                if hasattr(packet.ip, 'src'):
                    ipsrc = str(packet.ip.src)
                if hasattr(packet.ip, 'dst'):
                    ipdst = str(packet.ip.dst)
            except Exception as e:
                logger.debug(f"IP serialization failed: {e}")
        
        # Safely get timestamp
        timestamp = ''
        try:
            if hasattr(packet, 'sniff_time') and packet.sniff_time:
                timestamp = packet.sniff_time.isoformat()
        except Exception as e:
            logger.debug(f"Timestamp serialization failed: {e}")
        
        # Safely get highest layer
        highest_layer = ''
        try:
            if hasattr(packet, 'highest_layer'):
                highest_layer = str(packet.highest_layer)
        except Exception as e:
            logger.debug(f"Highest layer serialization failed: {e}")
        
        return {
            'time_stamp': timestamp,
            'ipsrc': ipsrc,
            'ipdst': ipdst,
            'srcport': srcport,
            'dstnport': dstport,
            'transport_layer': str(transport_layer) if transport_layer else '',
            'highest_layer': highest_layer,
        }
    except Exception as e:
        logger.error(f"Error serializing packet: {e}")
        return {
            'time_stamp': '',
            'ipsrc': '',
            'ipdst': '',
            'srcport': '',
            'dstnport': '',
            'transport_layer': '',
            'highest_layer': '',
        }

captured_packets = []

# Secure API endpoints
@app.route('/data', methods=['GET'])
@require_api_key
def data():
    serialized_packets = [serialize_packet(packet) for packet in captured_packets]
    return jsonify(serialized_packets)

@app.route('/alerts', methods=['GET'])
@require_api_key
def get_alerts():
    """Get security alerts"""
    alerts_data = []
    for alert in security_monitor.alerts:
        alerts_data.append({
            'id': alert.id,
            'type': alert.alert_type,
            'severity': alert.severity,
            'message': alert.message,
            'source_ip': alert.source_ip,
            'target_ip': alert.target_ip,
            'timestamp': alert.timestamp.isoformat()
        })
    return jsonify(alerts_data)

@app.route('/network_stats', methods=['GET'])
@require_api_key
def network_stats():
    """Get network statistics and baseline info"""
    return jsonify({
        'gateway_ip': security_monitor.baseline.gateway_ip,
        'gateway_mac': security_monitor.baseline.gateway_mac,
        'known_devices': len(security_monitor.baseline.known_devices),
        'total_alerts': len(security_monitor.alerts),
        'blacklisted_ips': len(security_monitor.blacklisted_ips),
        'arp_table_size': len(security_monitor.arp_table)
    })

@app.route('/network_topology', methods=['GET'])
@require_api_key
def network_topology():
    """Get network topology and device connections"""
    try:
        # Build network topology from captured packets
        devices = {}
        connections = []
        
        for packet in captured_packets[-100:]:  # Last 100 packets for topology
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Add devices
                if src_ip not in devices:
                    devices[src_ip] = {
                        'ip': src_ip,
                        'type': 'internal' if check_if_private_ipadress(src_ip) else 'external',
                        'first_seen': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
                        'last_seen': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
                        'protocols': set(),
                        'ports': set()
                    }
                else:
                    devices[src_ip]['last_seen'] = packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else ''
                
                if dst_ip not in devices:
                    devices[dst_ip] = {
                        'ip': dst_ip,
                        'type': 'internal' if check_if_private_ipadress(dst_ip) else 'external',
                        'first_seen': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
                        'last_seen': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else '',
                        'protocols': set(),
                        'ports': set()
                    }
                else:
                    devices[dst_ip]['last_seen'] = packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else ''
                
                # Add connection
                connection = {
                    'source': src_ip,
                    'target': dst_ip,
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown',
                    'timestamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else ''
                }
                
                if connection not in connections:
                    connections.append(connection)
                
                # Add protocol and port info
                if hasattr(packet, 'transport_layer'):
                    devices[src_ip]['protocols'].add(packet.transport_layer)
                    devices[dst_ip]['protocols'].add(packet.transport_layer)
                
                if hasattr(packet, 'tcp'):
                    if hasattr(packet.tcp, 'srcport'):
                        devices[src_ip]['ports'].add(packet.tcp.srcport)
                    if hasattr(packet.tcp, 'dstport'):
                        devices[dst_ip]['ports'].add(packet.tcp.dstport)
                elif hasattr(packet, 'udp'):
                    if hasattr(packet.udp, 'srcport'):
                        devices[src_ip]['ports'].add(packet.udp.srcport)
                    if hasattr(packet.udp, 'dstport'):
                        devices[dst_ip]['ports'].add(packet.udp.dstport)
        
        # Convert sets to lists for JSON serialization
        for device in devices.values():
            device['protocols'] = list(device['protocols'])
            device['ports'] = list(device['ports'])
        
        return jsonify({
            'devices': list(devices.values()),
            'connections': connections,
            'total_devices': len(devices),
            'total_connections': len(connections)
        })
        
    except Exception as e:
        logger.error(f"Error generating network topology: {e}")
        return jsonify({'error': 'Failed to generate topology'}), 500

@app.route('/traffic_analytics', methods=['GET'])
@require_api_key
def traffic_analytics():
    """Get detailed traffic analytics and trends"""
    try:
        # Analyze traffic patterns
        protocol_stats = defaultdict(int)
        port_stats = defaultdict(int)
        ip_traffic = defaultdict(int)
        hourly_traffic = defaultdict(int)
        
        if not captured_packets:
            # Return empty data structure if no packets
            return jsonify({
                'protocol_distribution': {},
                'top_source_ips': [],
                'top_destination_ports': [],
                'hourly_traffic': {},
                'alert_severity_distribution': {},
                'total_packets_analyzed': 0
            })
        
        for packet in captured_packets:
            try:
                if hasattr(packet, 'transport_layer') and packet.transport_layer:
                    protocol_stats[str(packet.transport_layer)] += 1
                
                if hasattr(packet, 'ip') and packet.ip:
                    try:
                        if hasattr(packet.ip, 'src') and packet.ip.src:
                            ip_traffic[str(packet.ip.src)] += 1
                        if hasattr(packet.ip, 'dst') and packet.ip.dst:
                            ip_traffic[str(packet.ip.dst)] += 1
                        
                        if hasattr(packet, 'sniff_time') and packet.sniff_time:
                            try:
                                hour = packet.sniff_time.strftime('%Y-%m-%d %H:00')
                                hourly_traffic[hour] += 1
                            except Exception as e:
                                logger.debug(f"Hour formatting failed: {e}")
                    except Exception as e:
                        logger.debug(f"IP processing failed: {e}")
                
                if hasattr(packet, 'tcp') and packet.tcp:
                    try:
                        if hasattr(packet.tcp, 'dstport') and packet.tcp.dstport:
                            port_stats[f"TCP/{packet.tcp.dstport}"] += 1
                    except Exception as e:
                        logger.debug(f"TCP processing failed: {e}")
                elif hasattr(packet, 'udp') and packet.udp:
                    try:
                        if hasattr(packet.udp, 'dstport') and packet.udp.dstport:
                            port_stats[f"UDP/{packet.udp.dstport}"] += 1
                    except Exception as e:
                        logger.debug(f"UDP processing failed: {e}")
                        
            except Exception as e:
                logger.debug(f"Individual packet processing failed: {e}")
                continue

        # Get top talkers
        top_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get recent alerts by severity
        alert_severity = defaultdict(int)
        try:
            for alert in security_monitor.alerts:
                alert_severity[str(alert.severity)] += 1
        except Exception as e:
            logger.debug(f"Alert processing failed: {e}")

        return jsonify({
            'protocol_distribution': dict(protocol_stats),
            'top_source_ips': [{'ip': str(ip), 'count': count} for ip, count in top_ips],
            'top_destination_ports': [{'port': str(port), 'count': count} for port, count in top_ports],
            'hourly_traffic': dict(hourly_traffic),
            'alert_severity_distribution': dict(alert_severity),
            'total_packets_analyzed': len(captured_packets)
        })
        
    except Exception as e:
        logger.error(f"Error generating traffic analytics: {e}", exc_info=True)
        # Return safe fallback data
        return jsonify({
            'protocol_distribution': {},
            'top_source_ips': [],
            'top_destination_ports': [],
            'hourly_traffic': {},
            'alert_severity_distribution': {},
            'total_packets_analyzed': 0,
            'error': 'Analytics generation failed, returning empty data'
        })


@app.route('/threat_indicators', methods=['GET'])
@require_api_key
def threat_indicators():
    """Get current threat indicators and risk assessment"""
    try:
        # Calculate risk scores
        risk_factors = {
            'high_alert_count': len([a for a in security_monitor.alerts if a.severity in ['HIGH', 'CRITICAL']]),
            'port_scan_attempts': len([a for a in security_monitor.alerts if 'PORT_SCAN' in a.alert_type]),
            'suspicious_connections': len([a for a in security_monitor.alerts if 'MALICIOUS_IP' in a.alert_type]),
            'unencrypted_traffic': len([a for a in security_monitor.alerts if 'UNENCRYPTED' in a.alert_type])
        }
        
        # Calculate overall risk score (0-100)
        risk_score = min(100, (
            risk_factors['high_alert_count'] * 10 +
            risk_factors['port_scan_attempts'] * 5 +
            risk_factors['suspicious_connections'] * 15 +
            risk_factors['unencrypted_traffic'] * 3
        ))
        
        # Get recent threats
        recent_threats = []
        for alert in list(security_monitor.alerts)[-20:]:  # Last 20 alerts
            recent_threats.append({
                'type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat(),
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip
            })
        
        return jsonify({
            'risk_score': risk_score,
            'risk_level': 'LOW' if risk_score < 30 else 'MEDIUM' if risk_score < 70 else 'HIGH',
            'risk_factors': risk_factors,
            'recent_threats': recent_threats,
            'blacklisted_ips': list(security_monitor.blacklisted_ips),
            'recommendations': [
                'Enable HTTPS for all web traffic' if risk_factors['unencrypted_traffic'] > 0 else None,
                'Review firewall rules for suspicious IPs' if risk_factors['suspicious_connections'] > 0 else None,
                'Monitor for port scanning activities' if risk_factors['port_scan_attempts'] > 0 else None,
                'Implement intrusion prevention system' if risk_score > 70 else None
            ]
        })
        
    except Exception as e:
        logger.error(f"Error generating threat indicators: {e}")
        return jsonify({'error': 'Failed to generate threat indicators'}), 500

@app.route('/block_ip', methods=['POST'])
@require_api_key
def block_ip():
    """Block an IP address using system firewall"""
    data = request.get_json()
    ip_to_block = data.get('ip')
    
    if not ip_to_block:
        return jsonify({'error': 'IP address required'}), 400
    
    try:
        # Add to blacklist
        security_monitor.blacklisted_ips.add(ip_to_block)
        
        # Block using system firewall
        block_ip_system(ip_to_block)
        
        logger.info(f"Blocked IP: {ip_to_block}")
        return jsonify({'message': f'IP {ip_to_block} blocked successfully'})
        
    except Exception as e:
        logger.error(f"Failed to block IP {ip_to_block}: {e}")
        return jsonify({'error': 'Failed to block IP'}), 500

@app.route('/settings', methods=['GET', 'POST'])
@require_api_key
def settings():
    """Get or update runtime settings"""
    if request.method == 'GET':
        return jsonify(app_settings)
    try:
        data = request.get_json() or {}
        # Coerce and update known settings only
        if 'portScanThreshold' in data:
            app_settings['port_scan_threshold'] = int(data['portScanThreshold'])
        if 'synFloodThreshold' in data:
            app_settings['syn_flood_threshold'] = int(data['synFloodThreshold'])
        if 'sessionReplayThreshold' in data:
            app_settings['session_replay_threshold'] = int(data['sessionReplayThreshold'])
        if 'autoBlock' in data:
            app_settings['auto_block'] = bool(data['autoBlock'])
        if 'autoBlockSeverity' in data:
            app_settings['auto_block_severity_threshold'] = str(data['autoBlockSeverity']).upper()
        return jsonify({'message': 'Settings updated', 'settings': app_settings})
    except Exception as e:
        logger.error(f"Failed to update settings: {e}")
        return jsonify({'error': 'Invalid settings payload'}), 400

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/events')
def events():
    """Real-time event stream for packets and alerts"""
    def generate():
        while True:
            # Send packet data
            if captured_packets:
                packet = captured_packets.pop(0)
                yield f"data: {json.dumps({'type': 'packet', 'data': serialize_packet(packet)})}\n\n"
            
            # Send alert data
            if security_monitor.alerts:
                alert = security_monitor.alerts[-1]  # Get latest alert
                alert_data = {
                    'type': 'alert',
                    'data': {
                        'id': alert.id,
                        'alert_type': alert.alert_type,
                        'severity': alert.severity,
                        'message': alert.message,
                        'source_ip': alert.source_ip,
                        'target_ip': alert.target_ip,
                        'timestamp': alert.timestamp.isoformat()
                    }
                }
                yield f"data: {json.dumps(alert_data)}\n\n"
            
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/report', methods=['POST'])
def secure_api_report():
    """Secure endpoint for receiving packet reports"""
    try:
        data = request.get_json()
        
        # Verify signature
        signature = data.get('signature')
        packet_data = data.get('data')
        
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            json.dumps(packet_data, default=str).encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Process the packet data

        logger.info(f"Received secure packet report: {packet_data}")
        return jsonify({'status': 'success'})

    except Exception as e:
        logger.error(f"Error processing secure report: {e}")
        return jsonify({'error': 'Processing failed'}), 500


def capture_packets():
    """Capture packets from the network interface and analyze them."""
    global captured_packets, capture
    
    while True:  # Continuous capture with restart capability
        try:
            logger.info("Starting packet capture...")
            for packet in capture.sniff_continuously(packet_count=500):
                try:
                    if packet:
                        check_packet_filter(packet)
                        captured_packets.append(packet)
                        if len(captured_packets) > 100:
                            captured_packets.pop(0)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            # Try to restart capture after a delay
            time.sleep(5)
            try:
                capture.close()
                capture = pyshark.LiveCapture(interface=network_interface)
                logger.info("Packet capture restarted successfully")
            except Exception as restart_error:
                logger.error(f"Failed to restart capture: {restart_error}")
                time.sleep(10)  # Wait longer before next attempt

if __name__ == '__main__':
    try:
        # Test network interface availability
        logger.info(f"Initializing network capture on interface: {network_interface}")
        
        # Start packet capture thread
        capture_thread = threading.Thread(target=capture_packets, daemon=True)
        capture_thread.start()
        logger.info("Packet capture thread started")
        
        # Configure Flask for production
        if ENABLE_HTTPS:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.load_cert_chain('cert.pem', 'key.pem')
                logger.info("Starting HTTPS server...")
                app.run(debug=False, host="0.0.0.0", port=5000, threaded=True, ssl_context=context)
            except FileNotFoundError:
                logger.error("SSL certificates not found. Falling back to HTTP mode.")
                logger.warning("Running in HTTP mode. Enable HTTPS for production!")
                app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
            except Exception as e:
                logger.error(f"HTTPS startup failed: {e}. Falling back to HTTP mode.")
                app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
        else:
            logger.warning("Running in HTTP mode. Enable HTTPS for production!")
            app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
            
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise