# threat_intel.py - Threat Intelligence Integration Module

import requests
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Set, Dict, List, Optional
import logging
import threading
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ThreatIndicator:
    indicator: str
    indicator_type: str  # 'ip', 'domain', 'hash', 'url'
    threat_type: str    # 'malware', 'botnet', 'phishing', 'c2'
    confidence: int     # 1-100
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str = ""

class ThreatIntelligenceManager:
    def __init__(self, update_interval_hours: int = 6):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        self.update_interval = timedelta(hours=update_interval_hours)
        self.last_update = None
        self.feeds = []
        self.running = False
        self.update_thread = None
        
        # Initialize with some basic threat feeds
        self.initialize_feeds()
        
    def initialize_feeds(self):
        """Initialize threat intelligence feeds"""
        # Note: In production, you would use real threat intelligence APIs
        # These are example configurations
        
        self.feeds = [
            {
                'name': 'AbuseIPDB',
                'type': 'ip',
                'url': 'https://api.abuseipdb.com/api/v2/blacklist',
                'headers': {'Key': 'YOUR_ABUSEIPDB_API_KEY'},
                'enabled': False  # Disabled by default - requires API key
            },
            {
                'name': 'MalwareDomainList',
                'type': 'domain',
                'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
                'enabled': True
            },
            {
                'name': 'EmergingThreats',
                'type': 'ip',
                'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'enabled': True
            },
            {
                'name': 'Feodo Tracker',
                'type': 'ip',
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'enabled': True
            }
        ]
    
    def start_updating(self):
        """Start automatic threat intelligence updates"""
        if self.running:
            return
            
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        logger.info("Threat intelligence auto-update started")
    
    def stop_updating(self):
        """Stop automatic updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join()
        logger.info("Threat intelligence auto-update stopped")
    
    def _update_loop(self):
        """Main update loop"""
        while self.running:
            try:
                if self._should_update():
                    self.update_all_feeds()
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in threat intelligence update loop: {e}")
                time.sleep(300)
    
    def _should_update(self) -> bool:
        """Check if it's time to update"""
        if self.last_update is None:
            return True
        return datetime.now() - self.last_update > self.update_interval
    
    def update_all_feeds(self):
        """Update all enabled threat intelligence feeds"""
        logger.info("Updating threat intelligence feeds...")
        
        for feed in self.feeds:
            if not feed.get('enabled', False):
                continue
                
            try:
                self._update_feed(feed)
            except Exception as e:
                logger.error(f"Failed to update feed {feed['name']}: {e}")
        
        self.last_update = datetime.now()
        logger.info(f"Updated threat intelligence. IPs: {len(self.malicious_ips)}, Domains: {len(self.malicious_domains)}")
    
    def _update_feed(self, feed: Dict):
        """Update a single threat intelligence feed"""
        try:
            headers = feed.get('headers', {})
            response = requests.get(feed['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            if feed['type'] == 'ip':
                self._parse_ip_feed(response.text, feed['name'])
            elif feed['type'] == 'domain':
                self._parse_domain_feed(response.text, feed['name'])
                
        except requests.RequestException as e:
            logger.error(f"Failed to fetch feed {feed['name']}: {e}")
        except Exception as e:
            logger.error(f"Error processing feed {feed['name']}: {e}")
    
    def _parse_ip_feed(self, content: str, source: str):
        """Parse IP-based threat feed"""
        lines = content.strip().split('\n')
        new_ips = 0
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Extract IP (handle different formats)
            ip = self._extract_ip_from_line(line)
            if ip and self._is_valid_ip(ip):
                if ip not in self.malicious_ips:
                    self.malicious_ips.add(ip)
                    new_ips += 1
                    
                    # Create threat indicator
                    indicator = ThreatIndicator(
                        indicator=ip,
                        indicator_type='ip',
                        threat_type='malicious',
                        confidence=80,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source
                    )
                    self.threat_indicators[ip] = indicator
        
        logger.info(f"Added {new_ips} new malicious IPs from {source}")
    
    def _parse_domain_feed(self, content: str, source: str):
        """Parse domain-based threat feed"""
        lines = content.strip().split('\n')
        new_domains = 0
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Extract domain (handle different formats)
            domain = self._extract_domain_from_line(line)
            if domain and self._is_valid_domain(domain):
                if domain not in self.malicious_domains:
                    self.malicious_domains.add(domain)
                    new_domains += 1
                    
                    # Create threat indicator
                    indicator = ThreatIndicator(
                        indicator=domain,
                        indicator_type='domain',
                        threat_type='malicious',
                        confidence=80,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        source=source
                    )
                    self.threat_indicators[domain] = indicator
        
        logger.info(f"Added {new_domains} new malicious domains from {source}")
    
    def _extract_ip_from_line(self, line: str) -> Optional[str]:
        """Extract IP address from a line"""
        import re
        
        # Common IP regex pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, line)
        return match.group() if match else None
    
    def _extract_domain_from_line(self, line: str) -> Optional[str]:
        """Extract domain from a line"""
        import re
        
        # Handle hosts file format (127.0.0.1 malicious.domain.com)
        if '127.0.0.1' in line or '0.0.0.0' in line:
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1]
                if self._is_valid_domain(domain):
                    return domain
        
        # Handle plain domain lists
        domain = line.strip()
        if self._is_valid_domain(domain):
            return domain
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            # Exclude private/reserved ranges for external threats
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name"""
        import re
        
        # Basic domain validation
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return False
        
        # Exclude localhost and local domains
        if domain in ['localhost', 'local'] or domain.endswith('.local'):
            return False
        
        return True
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if an IP is known to be malicious"""
        return ip in self.malicious_ips
    
    def is_malicious_domain(self, domain: str) -> bool:
        """Check if a domain is known to be malicious"""
        return domain in self.malicious_domains
    
    def get_threat_info(self, indicator: str) -> Optional[ThreatIndicator]:
        """Get threat information for an indicator"""
        return self.threat_indicators.get(indicator)
    
    def add_custom_indicator(self, indicator: str, indicator_type: str, 
                           threat_type: str, confidence: int = 90, 
                           description: str = ""):
        """Add a custom threat indicator"""
        threat_indicator = ThreatIndicator(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_type=threat_type,
            confidence=confidence,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="custom",
            description=description
        )
        
        self.threat_indicators[indicator] = threat_indicator
        
        if indicator_type == 'ip':
            self.malicious_ips.add(indicator)
        elif indicator_type == 'domain':
            self.malicious_domains.add(indicator)
        
        logger.info(f"Added custom threat indicator: {indicator}")
    
    def remove_indicator(self, indicator: str):
        """Remove a threat indicator"""
        if indicator in self.threat_indicators:
            threat_info = self.threat_indicators[indicator]
            del self.threat_indicators[indicator]
            
            if threat_info.indicator_type == 'ip':
                self.malicious_ips.discard(indicator)
            elif threat_info.indicator_type == 'domain':
                self.malicious_domains.discard(indicator)
            
            logger.info(f"Removed threat indicator: {indicator}")
    
    def get_stats(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'total_indicators': len(self.threat_indicators),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'feeds_enabled': sum(1 for feed in self.feeds if feed.get('enabled', False))
        }
    
    def export_indicators(self, file_format: str = 'json') -> str:
        """Export threat indicators to file"""
        if file_format == 'json':
            data = {
                'export_time': datetime.now().isoformat(),
                'indicators': [
                    {
                        'indicator': ti.indicator,
                        'type': ti.indicator_type,
                        'threat_type': ti.threat_type,
                        'confidence': ti.confidence,
                        'source': ti.source,
                        'description': ti.description,
                        'first_seen': ti.first_seen.isoformat(),
                        'last_seen': ti.last_seen.isoformat()
                    }
                    for ti in self.threat_indicators.values()
                ]
            }
            return json.dumps(data, indent=2)
        
        elif file_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Indicator', 'Type', 'Threat Type', 'Confidence', 'Source', 'Description', 'First Seen', 'Last Seen'])
            
            for ti in self.threat_indicators.values():
                writer.writerow([
                    ti.indicator, ti.indicator_type, ti.threat_type,
                    ti.confidence, ti.source, ti.description,
                    ti.first_seen.isoformat(), ti.last_seen.isoformat()
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported export format: {file_format}")

# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create threat intelligence manager
    ti_manager = ThreatIntelligenceManager()
    
    # Add some custom indicators for testing
    ti_manager.add_custom_indicator("192.168.1.100", "ip", "malware", 95, "Test malicious IP")
    ti_manager.add_custom_indicator("evil.example.com", "domain", "phishing", 90, "Test malicious domain")
    
    # Test lookups
    print(f"Is 192.168.1.100 malicious? {ti_manager.is_malicious_ip('192.168.1.100')}")
    print(f"Is evil.example.com malicious? {ti_manager.is_malicious_domain('evil.example.com')}")
    
    # Get stats
    stats = ti_manager.get_stats()
    print(f"Threat Intelligence Stats: {json.dumps(stats, indent=2)}")
    
    # Start auto-updating (would run in background)
    # ti_manager.start_updating()