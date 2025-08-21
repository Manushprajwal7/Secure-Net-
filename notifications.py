# notifications.py - Multi-channel notification system for security alerts

import smtplib
import json
import requests
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import threading
import queue
import time

logger = logging.getLogger(__name__)

@dataclass
class NotificationChannel:
    name: str
    type: str  # 'email', 'slack', 'discord', 'webhook', 'sms'
    config: Dict
    enabled: bool = True
    rate_limit: Optional[int] = None  # Max notifications per hour

class NotificationManager:
    def __init__(self):
        self.channels: List[NotificationChannel] = []
        self.notification_queue = queue.Queue()
        self.rate_limits = {}  # Channel -> list of timestamps
        self.worker_thread = None
        self.running = False
        
    def add_channel(self, channel: NotificationChannel):
        """Add a notification channel"""
        self.channels.append(channel)
        logger.info(f"Added notification channel: {channel.name} ({channel.type})")
        
    def remove_channel(self, channel_name: str):
        """Remove a notification channel by name"""
        self.channels = [ch for ch in self.channels if ch.name != channel_name]
        logger.info(f"Removed notification channel: {channel_name}")
        
    def start_worker(self):
        """Start the notification worker thread"""
        if self.running:
            return
            
        self.running = True
        self.worker_thread = threading.Thread(target=self._notification_worker, daemon=True)
        self.worker_thread.start()
        logger.info("Notification worker started")
        
    def stop_worker(self):
        """Stop the notification worker"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info("Notification worker stopped")
        
    def _notification_worker(self):
        """Worker thread to process notifications"""
        while self.running:
            try:
                # Get notification from queue (blocking with timeout)
                notification = self.notification_queue.get(timeout=1)
                self._process_notification(notification)
                self.notification_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing notification: {e}")
                
    def _process_notification(self, notification: Dict):
        """Process a single notification"""
        for channel in self.channels:
            if not channel.enabled:
                continue
                
            # Check rate limits
            if not self._check_rate_limit(channel):
                logger.warning(f"Rate limit exceeded for channel {channel.name}")
                continue
                
            try:
                if channel.type == 'email':
                    self._send_email(notification, channel)
                elif channel.type == 'slack':
                    self._send_slack(notification, channel)
                elif channel.type == 'discord':
                    self._send_discord(notification, channel)
                elif channel.type == 'webhook':
                    self._send_webhook(notification, channel)
                elif channel.type == 'sms':
                    self._send_sms(notification, channel)
                else:
                    logger.warning(f"Unknown notification type: {channel.type}")
                    
            except Exception as e:
                logger.error(f"Failed to send notification via {channel.name}: {e}")
                
    def _check_rate_limit(self, channel: NotificationChannel) -> bool:
        """Check if channel is within rate limits"""
        if not channel.rate_limit:
            return True
            
        now = datetime.now()
        hour_ago = now.timestamp() - 3600  # 1 hour ago
        
        # Initialize rate limit tracking for channel
        if channel.name not in self.rate_limits:
            self.rate_limits[channel.name] = []
            
        # Remove old timestamps
        self.rate_limits[channel.name] = [
            ts for ts in self.rate_limits[channel.name] if ts > hour_ago
        ]
        
        # Check if under limit
        if len(self.rate_limits[channel.name]) >= channel.rate_limit:
            return False
            
        # Add current timestamp
        self.rate_limits[channel.name].append(now.timestamp())
        return True
        
    def _send_email(self, notification: Dict, channel: NotificationChannel):
        """Send email notification"""
        config = channel.config
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = f"[{notification['severity']}] {notification['title']}"
        
        # Create HTML body
        html_body = f"""
        <html>
        <head></head>
        <body>
            <h2 style="color: {'#dc3545' if notification['severity'] == 'CRITICAL' else '#fd7e14' if notification['severity'] == 'HIGH' else '#ffc107' if notification['severity'] == 'MEDIUM' else '#28a745'};">
                Security Alert: {notification['title']}
            </h2>
            <p><strong>Severity:</strong> {notification['severity']}</p>
            <p><strong>Time:</strong> {notification['timestamp']}</p>
            <p><strong>Source IP:</strong> {notification.get('source_ip', 'N/A')}</p>
            <p><strong>Target IP:</strong> {notification.get('target_ip', 'N/A')}</p>
            <p><strong>Description:</strong></p>
            <p>{notification['message']}</p>
            
            <hr>
            <p><small>This alert was generated by Network Security Monitor</small></p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email
        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            if config.get('use_tls', True):
                server.starttls()
            if config.get('username') and config.get('password'):
                server.login(config['username'], config['password'])
            server.send_message(msg)
            
        logger.info(f"Email notification sent via {channel.name}")
        
    def _send_slack(self, notification: Dict, channel: NotificationChannel):
        """Send Slack notification"""
        config = channel.config
        
        # Map severity to colors
        color_map = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        
        # Create Slack message
        slack_message = {
            "text": f"Security Alert: {notification['title']}",
            "attachments": [
                {
                    "color": color_map.get(notification['severity'], '#6c757d'),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": notification['severity'],
                            "short": True
                        },
                        {
                            "title": "Time",
                            "value": notification['timestamp'],
                            "short": True
                        },
                        {
                            "title": "Source IP",
                            "value": notification.get('source_ip', 'N/A'),
                            "short": True
                        },
                        {
                            "title": "Target IP",
                            "value": notification.get('target_ip', 'N/A'),
                            "short": True
                        },
                        {
                            "title": "Description",
                            "value": notification['message'],
                            "short": False
                        }
                    ],
                    "footer": "Network Security Monitor",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        # Send to Slack
        response = requests.post(
            config['webhook_url'],
            json=slack_message,
            timeout=10
        )
        response.raise_for_status()
        
        logger.info(f"Slack notification sent via {channel.name}")
        
    def _send_discord(self, notification: Dict, channel: NotificationChannel):
        """Send Discord notification"""
        config = channel.config
        
        # Map severity to colors (Discord uses decimal colors)
        color_map = {
            'CRITICAL': 0xdc3545,
            'HIGH': 0xfd7e14,
            'MEDIUM': 0xffc107,
            'LOW': 0x28a745
        }
        
        # Create Discord embed
        discord_message = {
            "content": f"🚨 **Security Alert: {notification['title']}**",
            "embeds": [
                {
                    "title": notification['title'],
                    "description": notification['message'],
                    "color": color_map.get(notification['severity'], 0x6c757d),
                    "fields": [
                        {
                            "name": "Severity",
                            "value": notification['severity'],
                            "inline": True
                        },
                        {
                            "name": "Source IP",
                            "value": notification.get('source_ip', 'N/A'),
                            "inline": True
                        },
                        {
                            "name": "Target IP",
                            "value": notification.get('target_ip', 'N/A'),
                            "inline": True
                        }
                    ],
                    "timestamp": notification['timestamp'],
                    "footer": {
                        "text": "Network Security Monitor"
                    }
                }
            ]
        }
        
        # Send to Discord
        response = requests.post(
            config['webhook_url'],
            json=discord_message,
            timeout=10
        )
        response.raise_for_status()
        
        logger.info(f"Discord notification sent via {channel.name}")
        
    def _send_webhook(self, notification: Dict, channel: NotificationChannel):
        """Send generic webhook notification"""
        config = channel.config
        
        # Prepare payload
        payload = {
            "alert": notification,
            "timestamp": datetime.now().isoformat(),
            "source": "network-security-monitor"
        }
        
        # Add custom headers if specified
        headers = {'Content-Type': 'application/json'}
        if 'headers' in config:
            headers.update(config['headers'])
            
        # Send webhook
        response = requests.post(
            config['url'],
            json=payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        
        logger.info(f"Webhook notification sent via {channel.name}")
        
    def _send_sms(self, notification: Dict, channel: NotificationChannel):
        """Send SMS notification (example using Twilio)"""
        config = channel.config
        
        # Create SMS message
        message = f"SECURITY ALERT [{notification['severity']}]: {notification['title']}\n"
        message += f"Time: {notification['timestamp']}\n"
        message += f"Details: {notification['message'][:100]}..."
        
        # This is an example - you would integrate with your SMS provider
        # For Twilio:
        if config.get('provider') == 'twilio':
            from twilio.rest import Client
            client = Client(config['account_sid'], config['auth_token'])
            
            for phone_number in config['phone_numbers']:
                client.messages.create(
                    body=message,
                    from_=config['from_number'],
                    to=phone_number
                )
                
        logger.info(f"SMS notification sent via {channel.name}")
        
    def send_notification(self, title: str, message: str, severity: str = 'MEDIUM',
                         source_ip: str = '', target_ip: str = ''):
        """Queue a notification for sending"""
        notification = {
            'title': title,
            'message': message,
            'severity': severity,
            'source_ip': source_ip,
            'target_ip': target_ip,
            'timestamp': datetime.now().isoformat()
        }
        
        self.notification_queue.put(notification)
        logger.debug(f"Notification queued: {title}")
        
    def send_test_notification(self, channel_name: str = None):
        """Send a test notification"""
        test_notification = {
            'title': 'Test Security Alert',
            'message': 'This is a test notification from Network Security Monitor. If you receive this, your notification system is working correctly.',
            'severity': 'LOW',
            'source_ip': '192.168.1.100',
            'target_ip': '192.168.1.1',
            'timestamp': datetime.now().isoformat()
        }
        
        if channel_name:
            # Send to specific channel
            channel = next((ch for ch in self.channels if ch.name == channel_name), None)
            if channel:
                self._process_notification(test_notification)
            else:
                logger.error(f"Channel not found: {channel_name}")
        else:
            # Send to all channels
            self.notification_queue.put(test_notification)
        
    def get_channel_stats(self) -> Dict:
        """Get notification channel statistics"""
        stats = {
            'total_channels': len(self.channels),
            'enabled_channels': len([ch for ch in self.channels if ch.enabled]),
            'channels_by_type': {},
            'rate_limit_status': {}
        }
        
        # Count channels by type
        for channel in self.channels:
            if channel.type not in stats['channels_by_type']:
                stats['channels_by_type'][channel.type] = 0
            stats['channels_by_type'][channel.type] += 1
            
        # Rate limit status
        for channel in self.channels:
            if channel.rate_limit:
                current_count = len(self.rate_limits.get(channel.name, []))
                stats['rate_limit_status'][channel.name] = {
                    'current': current_count,
                    'limit': channel.rate_limit,
                    'remaining': max(0, channel.rate_limit - current_count)
                }
                
        return stats

# Utility functions for easy setup
def create_email_channel(name: str, smtp_server: str, smtp_port: int,
                        from_email: str, to_emails: List[str],
                        username: str = None, password: str = None,
                        use_tls: bool = True, rate_limit: int = 10) -> NotificationChannel:
    """Create an email notification channel"""
    config = {
        'smtp_server': smtp_server,
        'smtp_port': smtp_port,
        'from_email': from_email,
        'to_emails': to_emails,
        'use_tls': use_tls
    }
    
    if username and password:
        config['username'] = username
        config['password'] = password
        
    return NotificationChannel(
        name=name,
        type='email',
        config=config,
        rate_limit=rate_limit
    )

def create_slack_channel(name: str, webhook_url: str, 
                        rate_limit: int = 20) -> NotificationChannel:
    """Create a Slack notification channel"""
    return NotificationChannel(
        name=name,
        type='slack',
        config={'webhook_url': webhook_url},
        rate_limit=rate_limit
    )

def create_discord_channel(name: str, webhook_url: str,
                          rate_limit: int = 30) -> NotificationChannel:
    """Create a Discord notification channel"""
    return NotificationChannel(
        name=name,
        type='discord',
        config={'webhook_url': webhook_url},
        rate_limit=rate_limit
    )

def create_webhook_channel(name: str, url: str, headers: Dict = None,
                          rate_limit: int = 50) -> NotificationChannel:
    """Create a generic webhook notification channel"""
    config = {'url': url}
    if headers:
        config['headers'] = headers
        
    return NotificationChannel(
        name=name,
        type='webhook',
        config=config,
        rate_limit=rate_limit
    )

def create_sms_channel(name: str, provider: str, phone_numbers: List[str],
                      provider_config: Dict, rate_limit: int = 5) -> NotificationChannel:
    """Create an SMS notification channel"""
    config = {
        'provider': provider,
        'phone_numbers': phone_numbers,
        **provider_config
    }
    
    return NotificationChannel(
        name=name,
        type='sms',
        config=config,
        rate_limit=rate_limit
    )

# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create notification manager
    notifier = NotificationManager()
    
    # Add email channel (example configuration)
    email_channel = create_email_channel(
        name="security_team_email",
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        from_email="security@company.com",
        to_emails=["admin@company.com", "security@company.com"],
        username="security@company.com",
        password="app_password_here",
        rate_limit=10
    )
    notifier.add_channel(email_channel)
    
    # Add Slack channel (example)
    slack_channel = create_slack_channel(
        name="security_alerts_slack",
        webhook_url="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
        rate_limit=20
    )
    notifier.add_channel(slack_channel)
    
    # Add Discord channel (example)
    discord_channel = create_discord_channel(
        name="security_alerts_discord",
        webhook_url="https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK",
        rate_limit=30
    )
    notifier.add_channel(discord_channel)
    
    # Start notification worker
    notifier.start_worker()
    
    # Send test notification
    notifier.send_notification(
        title="Port Scan Detected",
        message="Multiple port scan attempts detected from IP 192.168.1.100. Immediate attention required.",
        severity="HIGH",
        source_ip="192.168.1.100",
        target_ip="192.168.1.1"
    )
    
    # Send test notification to specific channel
    notifier.send_test_notification("security_team_email")
    
    # Get statistics
    stats = notifier.get_channel_stats()
    print(f"Notification Stats: {json.dumps(stats, indent=2)}")
    
    # Wait a bit for notifications to be sent
    time.sleep(2)
    
    # Stop worker
    notifier.stop_worker()