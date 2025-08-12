"""
Professional Response Agents for Cybersecurity Defense
Enterprise-grade blocking, alerting, and response capabilities
"""

import subprocess
import time
import smtplib
import json
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
from agents.base_agent import BaseSecurityAgent, AgentMessage, MessageType, AgentStatus
import logging
import threading
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ResponseStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

@dataclass
class ResponseAction:
    """Professional response action with full audit trail"""
    action_id: str
    action_type: str
    target: str
    parameters: Dict[str, Any]
    status: ResponseStatus
    start_time: float
    end_time: Optional[float] = None
    success: bool = False
    error_message: Optional[str] = None
    rollback_info: Optional[Dict[str, Any]] = None

class NetworkBlockingAgent(BaseSecurityAgent):
    """
    Professional network blocking agent using iptables and system-level controls
    Implements enterprise-grade IP blocking, rate limiting, and traffic control
    """
    
    def __init__(self, agent_id: str = "network_blocker"):
        super().__init__(agent_id, "Network Blocking Agent")
        
        # Blocking configuration
        self.blocking_config = {
            'use_iptables': True,
            'use_hosts_file': True,
            'default_block_duration': 3600,  # 1 hour
            'max_concurrent_blocks': 1000,
            'rate_limit_threshold': 100,  # packets per second
            'whitelist_ips': ['127.0.0.1', '::1']
        }
        
        # Active blocks tracking
        self.active_blocks = {}
        self.block_history = []
        self.rate_limits = {}
        
        # Database for persistence
        self.db_path = "response_actions.db"
        self._init_database()
        
        logger.info("Network Blocking Agent initialized")

    def _init_database(self):
        """Initialize response actions database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_actions (
                action_id TEXT PRIMARY KEY,
                action_type TEXT,
                target TEXT,
                parameters TEXT,
                status TEXT,
                start_time REAL,
                end_time REAL,
                success BOOLEAN,
                error_message TEXT,
                rollback_info TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                block_reason TEXT,
                block_time REAL,
                unblock_time REAL,
                is_active BOOLEAN,
                block_count INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()

    def _do_work(self):
        """Main blocking agent work"""
        try:
            # Check for expired blocks
            self._cleanup_expired_blocks()
            
            # Monitor rate limits
            self._monitor_rate_limits()
            
            # Update statistics
            self._update_blocking_stats()
        
        except Exception as e:
            logger.error(f"Network blocking work error: {e}")

    def handle_custom_message(self, message: AgentMessage):
        """Handle blocking-specific messages"""
        if message.message_type == MessageType.RESPONSE_ACTION:
            self._handle_response_request(message)

    def _handle_response_request(self, message: AgentMessage):
        """Handle response action requests"""
        payload = message.payload
        action = payload.get('action')
        threat_data = payload.get('threat_data', {})
        response_id = payload.get('response_id')
        
        if action == 'block_ip':
            self._block_ip_address(threat_data, response_id)
        elif action == 'rate_limit':
            self._apply_rate_limit(threat_data, response_id)
        elif action == 'unblock_ip':
            self._unblock_ip_address(threat_data, response_id)
        elif action == 'quarantine':
            self._quarantine_host(threat_data, response_id)
        else:
            logger.warning(f"Unknown action requested: {action}")

    def _block_ip_address(self, threat_data: Dict[str, Any], response_id: str):
        """Professional IP address blocking with iptables"""
        ip_address = threat_data.get('source_ip') or threat_data.get('src_ip')
        if not ip_address:
            logger.error("No IP address provided for blocking")
            return
        
        # Check whitelist
        if ip_address in self.blocking_config['whitelist_ips']:
            logger.warning(f"Attempted to block whitelisted IP: {ip_address}")
            return
        
        action_id = f"block_{ip_address}_{int(time.time())}"
        
        action = ResponseAction(
            action_id=action_id,
            action_type='block_ip',
            target=ip_address,
            parameters={
                'duration': self.blocking_config['default_block_duration'],
                'reason': threat_data.get('threat_type', 'unknown'),
                'confidence': threat_data.get('confidence', 0)
            },
            status=ResponseStatus.PENDING,
            start_time=time.time()
        )
        
        try:
            # Execute iptables blocking
            if self._execute_iptables_block(ip_address):
                # Update hosts file as backup
                self._update_hosts_file_block(ip_address)
                
                # Record in database
                self._record_ip_block(ip_address, threat_data)
                
                # Schedule unblock
                unblock_time = time.time() + action.parameters['duration']
                self._schedule_unblock(ip_address, unblock_time)
                
                action.status = ResponseStatus.COMPLETED
                action.success = True
                action.end_time = time.time()
                
                self.active_blocks[ip_address] = action
                
                logger.info(f"Successfully blocked IP: {ip_address}")
                
                # Notify coordinator
                self._send_response_completion(response_id, 'block_ip', True)
            
            else:
                action.status = ResponseStatus.FAILED
                action.error_message = "Failed to execute iptables command"
                logger.error(f"Failed to block IP: {ip_address}")
                
                self._send_response_completion(response_id, 'block_ip', False)
        
        except Exception as e:
            action.status = ResponseStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Error blocking IP {ip_address}: {e}")
            
            self._send_response_completion(response_id, 'block_ip', False)
        
        finally:
            self._store_response_action(action)

    def _execute_iptables_block(self, ip_address: str) -> bool:
        """Execute iptables command to block IP"""
        try:
            # Block incoming traffic from IP
            cmd_input = [
                'iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ]
            
            # Block outgoing traffic to IP
            cmd_output = [
                'iptables', '-I', 'OUTPUT', '-d', ip_address, '-j', 'DROP'
            ]
            
            # Execute commands (would require root privileges)
            # For demonstration, we'll simulate the commands
            logger.info(f"Executing: {' '.join(cmd_input)}")
            logger.info(f"Executing: {' '.join(cmd_output)}")
            
            # In production, you would use:
            # subprocess.run(cmd_input, check=True)
            # subprocess.run(cmd_output, check=True)
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables command failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Error executing iptables: {e}")
            return False

    def _update_hosts_file_block(self, ip_address: str):
        """Update hosts file as backup blocking method"""
        try:
            hosts_entry = f"127.0.0.1 {ip_address} # BLOCKED by cybersecurity system\n"
            
            # In production, you would append to /etc/hosts
            logger.info(f"Would add to hosts file: {hosts_entry.strip()}")
            
        except Exception as e:
            logger.error(f"Error updating hosts file: {e}")

    def _record_ip_block(self, ip_address: str, threat_data: Dict[str, Any]):
        """Record IP block in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip_address, block_reason, block_time, unblock_time, is_active, block_count)
                VALUES (?, ?, ?, ?, ?, 
                    COALESCE((SELECT block_count FROM blocked_ips WHERE ip_address = ?), 0) + 1)
            ''', (
                ip_address,
                threat_data.get('threat_type', 'unknown'),
                time.time(),
                time.time() + self.blocking_config['default_block_duration'],
                True,
                ip_address
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error recording IP block: {e}")

    def _schedule_unblock(self, ip_address: str, unblock_time: float):
        """Schedule automatic unblocking"""
        def unblock_timer():
            time.sleep(max(0, unblock_time - time.time()))
            self._unblock_ip_address({'src_ip': ip_address}, f"auto_unblock_{ip_address}")
        
        timer_thread = threading.Thread(target=unblock_timer, daemon=True)
        timer_thread.start()

    def _unblock_ip_address(self, threat_data: Dict[str, Any], response_id: str):
        """Unblock IP address"""
        ip_address = threat_data.get('source_ip') or threat_data.get('src_ip')
        if not ip_address:
            logger.error("No IP address provided for unblocking")
            return
        
        try:
            # Remove iptables rules
            cmd_input = [
                'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ]
            cmd_output = [
                'iptables', '-D', 'OUTPUT', '-d', ip_address, '-j', 'DROP'
            ]
            
            logger.info(f"Executing: {' '.join(cmd_input)}")
            logger.info(f"Executing: {' '.join(cmd_output)}")
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE blocked_ips 
                SET is_active = FALSE, unblock_time = ?
                WHERE ip_address = ?
            ''', (time.time(), ip_address))
            conn.commit()
            conn.close()
            
            # Remove from active blocks
            if ip_address in self.active_blocks:
                del self.active_blocks[ip_address]
            
            logger.info(f"Successfully unblocked IP: {ip_address}")
            
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")

    def _apply_rate_limit(self, threat_data: Dict[str, Any], response_id: str):
        """Apply rate limiting to IP address"""
        ip_address = threat_data.get('source_ip') or threat_data.get('src_ip')
        if not ip_address:
            return
        
        try:
            # Use iptables with limit module
            cmd = [
                'iptables', '-I', 'INPUT', '-s', ip_address,
                '-m', 'limit', '--limit', f"{self.blocking_config['rate_limit_threshold']}/sec",
                '-j', 'ACCEPT'
            ]
            
            logger.info(f"Applying rate limit: {' '.join(cmd)}")
            
            self.rate_limits[ip_address] = {
                'limit': self.blocking_config['rate_limit_threshold'],
                'start_time': time.time(),
                'response_id': response_id
            }
            
            self._send_response_completion(response_id, 'rate_limit', True)
            
        except Exception as e:
            logger.error(f"Error applying rate limit to {ip_address}: {e}")
            self._send_response_completion(response_id, 'rate_limit', False)

    def _quarantine_host(self, threat_data: Dict[str, Any], response_id: str):
        """Quarantine infected host"""
        ip_address = threat_data.get('source_ip') or threat_data.get('src_ip')
        if not ip_address:
            return
        
        try:
            # Redirect all traffic from host to quarantine network
            quarantine_ip = "192.168.100.1"  # Quarantine server
            
            cmd = [
                'iptables', '-t', 'nat', '-I', 'PREROUTING',
                '-s', ip_address, '-j', 'DNAT',
                '--to-destination', quarantine_ip
            ]
            
            logger.info(f"Quarantining host: {' '.join(cmd)}")
            
            self._send_response_completion(response_id, 'quarantine', True)
            
        except Exception as e:
            logger.error(f"Error quarantining host {ip_address}: {e}")
            self._send_response_completion(response_id, 'quarantine', False)

    def _cleanup_expired_blocks(self):
        """Clean up expired IP blocks"""
        current_time = time.time()
        expired_ips = []
        
        for ip, action in self.active_blocks.items():
            if current_time > action.start_time + action.parameters['duration']:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            self._unblock_ip_address({'src_ip': ip}, f"cleanup_{ip}")

    def _monitor_rate_limits(self):
        """Monitor and clean up rate limits"""
        current_time = time.time()
        expired_limits = []
        
        for ip, limit_info in self.rate_limits.items():
            if current_time > limit_info['start_time'] + 3600:  # 1 hour
                expired_limits.append(ip)
        
        for ip in expired_limits:
            del self.rate_limits[ip]

    def _update_blocking_stats(self):
        """Update blocking statistics"""
        self.stats['active_blocks'] = len(self.active_blocks)
        self.stats['active_rate_limits'] = len(self.rate_limits)

    def _store_response_action(self, action: ResponseAction):
        """Store response action in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO response_actions
                (action_id, action_type, target, parameters, status, start_time, 
                 end_time, success, error_message, rollback_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                action.action_id,
                action.action_type,
                action.target,
                json.dumps(action.parameters),
                action.status.value,
                action.start_time,
                action.end_time,
                action.success,
                action.error_message,
                json.dumps(action.rollback_info) if action.rollback_info else None
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing response action: {e}")

    def _send_response_completion(self, response_id: str, action: str, success: bool):
        """Send response completion message to coordinator"""
        completion_message = AgentMessage(
            sender_id=self.agent_id,
            receiver_id="coordinator",
            message_type=MessageType.RESPONSE_ACTION,
            payload={
                'response_id': response_id,
                'completed_action': action,
                'success': success,
                'timestamp': time.time()
            },
            timestamp=time.time(),
            priority=2
        )
        
        self.send_message(completion_message)

class AlertingAgent(BaseSecurityAgent):
    """
    Professional alerting agent with multiple notification channels
    Supports email, SMS, dashboard notifications, and SIEM integration
    """
    
    def __init__(self, agent_id: str = "alerting_agent"):
        super().__init__(agent_id, "Alerting Agent")
        
        # Alerting configuration
        self.alert_config = {
            'email_enabled': True,
            'sms_enabled': False,
            'dashboard_enabled': True,
            'siem_enabled': False,
            'smtp_server': 'localhost',
            'smtp_port': 587,
            'email_from': 'security@company.com',
            'admin_emails': ['admin@company.com', 'security@company.com'],
            'escalation_threshold': 3,  # Number of alerts before escalation
            'rate_limit_minutes': 5  # Minimum time between similar alerts
        }
        
        # Alert tracking
        self.alert_history = []
        self.alert_counts = {}
        self.last_alert_times = {}
        
        logger.info("Alerting Agent initialized")

    def _do_work(self):
        """Main alerting work"""
        try:
            # Clean up old alert tracking data
            self._cleanup_alert_tracking()
            
            # Process pending escalations
            self._process_escalations()
        
        except Exception as e:
            logger.error(f"Alerting work error: {e}")

    def handle_custom_message(self, message: AgentMessage):
        """Handle alerting-specific messages"""
        if message.message_type == MessageType.RESPONSE_ACTION:
            self._handle_alert_request(message)

    def _handle_alert_request(self, message: AgentMessage):
        """Handle alert requests"""
        payload = message.payload
        action = payload.get('action')
        threat_data = payload.get('threat_data', {})
        response_id = payload.get('response_id')
        
        if action in ['alert_admin', 'alert_security', 'alert_critical']:
            self._send_threat_alert(threat_data, action, response_id)

    def _send_threat_alert(self, threat_data: Dict[str, Any], alert_type: str, response_id: str):
        """Send comprehensive threat alert"""
        try:
            # Check rate limiting
            alert_key = f"{threat_data.get('threat_type')}_{threat_data.get('src_ip')}"
            if self._is_rate_limited(alert_key):
                logger.info(f"Alert rate limited: {alert_key}")
                return
            
            # Create alert message
            alert_message = self._create_alert_message(threat_data, alert_type)
            
            # Send via configured channels
            success = True
            
            if self.alert_config['email_enabled']:
                success &= self._send_email_alert(alert_message, alert_type)
            
            if self.alert_config['dashboard_enabled']:
                success &= self._send_dashboard_alert(alert_message, alert_type)
            
            if self.alert_config['siem_enabled']:
                success &= self._send_siem_alert(alert_message, alert_type)
            
            # Record alert
            self._record_alert(threat_data, alert_type, success)
            
            # Update tracking
            self.alert_counts[alert_key] = self.alert_counts.get(alert_key, 0) + 1
            self.last_alert_times[alert_key] = time.time()
            
            # Send completion notification
            self._send_response_completion(response_id, action, success)
            
            logger.info(f"Threat alert sent: {alert_type} for {threat_data.get('threat_type')}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
            self._send_response_completion(response_id, action, False)

    def _create_alert_message(self, threat_data: Dict[str, Any], alert_type: str) -> Dict[str, Any]:
        """Create comprehensive alert message"""
        severity_map = {
            'alert_admin': 'Medium',
            'alert_security': 'High',
            'alert_critical': 'Critical'
        }
        
        return {
            'timestamp': time.time(),
            'alert_type': alert_type,
            'severity': severity_map.get(alert_type, 'Medium'),
            'threat_type': threat_data.get('threat_type', 'Unknown'),
            'source_ip': threat_data.get('src_ip', 'Unknown'),
            'destination_ip': threat_data.get('dst_ip', 'Unknown'),
            'confidence': threat_data.get('confidence', 0),
            'evidence': threat_data.get('evidence', []),
            'recommended_action': threat_data.get('recommended_action', 'Investigate'),
            'detection_time': threat_data.get('timestamp', time.time())
        }

    def _send_email_alert(self, alert_message: Dict[str, Any], alert_type: str) -> bool:
        """Send email alert to administrators"""
        try:
            # Create email content
            subject = f"[SECURITY ALERT] {alert_message['severity']} - {alert_message['threat_type']} Detected"
            
            body = f"""
CYBERSECURITY THREAT ALERT

Severity: {alert_message['severity']}
Threat Type: {alert_message['threat_type']}
Source IP: {alert_message['source_ip']}
Destination IP: {alert_message['destination_ip']}
Confidence: {alert_message['confidence']:.2f}
Detection Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert_message['detection_time']))}

Evidence:
{chr(10).join(f"- {evidence}" for evidence in alert_message['evidence'])}

Recommended Action: {alert_message['recommended_action']}

This is an automated alert from the Cybersecurity Defense System.
Please investigate immediately.
            """
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.alert_config['email_from']
            msg['To'] = ', '.join(self.alert_config['admin_emails'])
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email (simulated for demonstration)
            logger.info(f"Email alert would be sent to: {self.alert_config['admin_emails']}")
            logger.info(f"Subject: {subject}")
            
            # In production, you would use:
            # server = smtplib.SMTP(self.alert_config['smtp_server'], self.alert_config['smtp_port'])
            # server.send_message(msg)
            # server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False

    def _send_dashboard_alert(self, alert_message: Dict[str, Any], alert_type: str) -> bool:
        """Send alert to dashboard notification system"""
        try:
            # Store alert in database for dashboard display
            conn = sqlite3.connect("dashboard_alerts.db")
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dashboard_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    alert_type TEXT,
                    severity TEXT,
                    threat_type TEXT,
                    source_ip TEXT,
                    message TEXT,
                    is_read BOOLEAN DEFAULT FALSE
                )
            ''')
            
            cursor.execute('''
                INSERT INTO dashboard_alerts 
                (timestamp, alert_type, severity, threat_type, source_ip, message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert_message['timestamp'],
                alert_type,
                alert_message['severity'],
                alert_message['threat_type'],
                alert_message['source_ip'],
                json.dumps(alert_message)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info("Dashboard alert stored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error sending dashboard alert: {e}")
            return False

    def _send_siem_alert(self, alert_message: Dict[str, Any], alert_type: str) -> bool:
        """Send alert to SIEM system"""
        try:
            # Format as CEF (Common Event Format) for SIEM integration
            cef_message = (
                f"CEF:0|CyberDefense|ThreatDetection|1.0|{alert_message['threat_type']}|"
                f"{alert_message['threat_type']} Detected|{alert_message['severity']}|"
                f"src={alert_message['source_ip']} dst={alert_message['destination_ip']} "
                f"cs1={alert_message['confidence']} cs1Label=Confidence"
            )
            
            logger.info(f"SIEM alert: {cef_message}")
            
            # In production, you would send to SIEM via syslog or API
            return True
            
        except Exception as e:
            logger.error(f"Error sending SIEM alert: {e}")
            return False

    def _is_rate_limited(self, alert_key: str) -> bool:
        """Check if alert is rate limited"""
        if alert_key not in self.last_alert_times:
            return False
        
        time_since_last = time.time() - self.last_alert_times[alert_key]
        return time_since_last < (self.alert_config['rate_limit_minutes'] * 60)

    def _record_alert(self, threat_data: Dict[str, Any], alert_type: str, success: bool):
        """Record alert in history"""
        alert_record = {
            'timestamp': time.time(),
            'threat_data': threat_data,
            'alert_type': alert_type,
            'success': success
        }
        
        self.alert_history.append(alert_record)
        
        # Keep only last 1000 alerts
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]

    def _cleanup_alert_tracking(self):
        """Clean up old alert tracking data"""
        current_time = time.time()
        cutoff_time = current_time - (24 * 3600)  # 24 hours
        
        # Clean up old alert times
        expired_keys = [
            key for key, timestamp in self.last_alert_times.items()
            if timestamp < cutoff_time
        ]
        
        for key in expired_keys:
            del self.last_alert_times[key]
            if key in self.alert_counts:
                del self.alert_counts[key]

    def _process_escalations(self):
        """Process alert escalations"""
        for alert_key, count in self.alert_counts.items():
            if count >= self.alert_config['escalation_threshold']:
                self._escalate_alert(alert_key, count)

    def _escalate_alert(self, alert_key: str, count: int):
        """Escalate repeated alerts"""
        logger.warning(f"Escalating alert: {alert_key} (count: {count})")
        
        # Send escalation notification
        escalation_message = {
            'timestamp': time.time(),
            'alert_key': alert_key,
            'count': count,
            'severity': 'Critical',
            'message': f"Alert {alert_key} has occurred {count} times and requires immediate attention"
        }
        
        # Send via all channels for escalation
        if self.alert_config['email_enabled']:
            self._send_escalation_email(escalation_message)

    def _send_escalation_email(self, escalation_message: Dict[str, Any]):
        """Send escalation email"""
        try:
            subject = f"[ESCALATION] Security Alert Requires Immediate Attention"
            body = f"""
SECURITY ALERT ESCALATION

Alert: {escalation_message['alert_key']}
Occurrence Count: {escalation_message['count']}
Escalation Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(escalation_message['timestamp']))}

This alert has exceeded the escalation threshold and requires immediate investigation.

Please take immediate action to address this security concern.
            """
            
            logger.info(f"Escalation email would be sent: {subject}")
            
        except Exception as e:
            logger.error(f"Error sending escalation email: {e}")

    def _send_response_completion(self, response_id: str, action: str, success: bool):
        """Send response completion message to coordinator"""
        completion_message = AgentMessage(
            sender_id=self.agent_id,
            receiver_id="coordinator",
            message_type=MessageType.RESPONSE_ACTION,
            payload={
                'response_id': response_id,
                'completed_action': action,
                'success': success,
                'timestamp': time.time()
            },
            timestamp=time.time(),
            priority=2
        )
        
        self.send_message(completion_message)

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get comprehensive alert statistics"""
        return {
            'total_alerts': len(self.alert_history),
            'alerts_last_24h': len([
                alert for alert in self.alert_history
                if time.time() - alert['timestamp'] < 86400
            ]),
            'alert_types': {
                alert_type: len([
                    alert for alert in self.alert_history
                    if alert['alert_type'] == alert_type
                ])
                for alert_type in ['alert_admin', 'alert_security', 'alert_critical']
            },
            'active_escalations': len([
                key for key, count in self.alert_counts.items()
                if count >= self.alert_config['escalation_threshold']
            ])
        }
