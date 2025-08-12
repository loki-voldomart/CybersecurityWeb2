"""
Coordination Agent for Multi-Agent Cybersecurity System
Central intelligence and decision-making hub
"""

import time
import threading
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from agents.base_agent import BaseSecurityAgent, AgentMessage, MessageType, AgentStatus
import logging
import json

logger = logging.getLogger(__name__)

class ThreatCorrelationEngine:
    """
    Advanced threat correlation and analysis engine
    Combines multiple agent inputs for comprehensive threat assessment
    """
    
    def __init__(self):
        self.threat_history = deque(maxlen=1000)
        self.correlation_rules = {
            'dos_port_scan_combo': {
                'threats': ['dos', 'port_scan'],
                'time_window': 300,  # 5 minutes
                'confidence_boost': 0.3,
                'severity_upgrade': True
            },
            'malware_phishing_combo': {
                'threats': ['malware', 'phishing'],
                'time_window': 600,  # 10 minutes
                'confidence_boost': 0.4,
                'severity_upgrade': True
            },
            'coordinated_attack': {
                'threats': ['dos', 'port_scan', 'malware'],
                'time_window': 900,  # 15 minutes
                'confidence_boost': 0.5,
                'severity_upgrade': True
            }
        }

    def correlate_threats(self, new_threat: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate new threat with historical data"""
        current_time = time.time()
        correlations = []
        
        # Add to history
        new_threat['timestamp'] = current_time
        self.threat_history.append(new_threat)
        
        # Check correlation rules
        for rule_name, rule in self.correlation_rules.items():
            correlation = self._check_correlation_rule(new_threat, rule, current_time)
            if correlation:
                correlations.append({
                    'rule': rule_name,
                    'related_threats': correlation['threats'],
                    'confidence_boost': rule['confidence_boost'],
                    'severity_upgrade': rule['severity_upgrade']
                })
        
        # Calculate final assessment
        final_confidence = new_threat.get('confidence', 0)
        final_severity = new_threat.get('severity', 'low')
        
        for correlation in correlations:
            final_confidence = min(1.0, final_confidence + correlation['confidence_boost'])
            if correlation['severity_upgrade']:
                final_severity = self._upgrade_severity(final_severity)
        
        return {
            'original_threat': new_threat,
            'correlations': correlations,
            'final_confidence': final_confidence,
            'final_severity': final_severity,
            'is_correlated': len(correlations) > 0
        }

    def _check_correlation_rule(self, new_threat: Dict, rule: Dict, current_time: float) -> Optional[Dict]:
        """Check if a correlation rule matches"""
        required_threats = set(rule['threats'])
        time_window = rule['time_window']
        
        # Find threats within time window
        recent_threats = [
            threat for threat in self.threat_history
            if current_time - threat['timestamp'] <= time_window
        ]
        
        # Group by threat type
        threat_types = defaultdict(list)
        for threat in recent_threats:
            threat_types[threat.get('threat_type')].append(threat)
        
        # Check if all required threat types are present
        found_types = set(threat_types.keys())
        if required_threats.issubset(found_types):
            return {
                'threats': {threat_type: threats for threat_type, threats in threat_types.items()
                           if threat_type in required_threats}
            }
        
        return None

    def _upgrade_severity(self, current_severity: str) -> str:
        """Upgrade threat severity level"""
        severity_levels = ['low', 'medium', 'high', 'critical']
        current_index = severity_levels.index(current_severity) if current_severity in severity_levels else 0
        new_index = min(len(severity_levels) - 1, current_index + 1)
        return severity_levels[new_index]

class CoordinatorAgent(BaseSecurityAgent):
    """
    Central coordination agent that manages all other security agents
    Makes final decisions and orchestrates responses
    """
    
    def __init__(self, agent_id: str = "coordinator"):
        super().__init__(agent_id, "Coordination Agent")
        
        # Managed agents
        self.managed_agents = {}
        self.agent_status = {}
        
        # Threat correlation engine
        self.correlation_engine = ThreatCorrelationEngine()
        
        # Decision making configuration
        self.decision_config = {
            'auto_response_threshold': 0.8,
            'human_approval_threshold': 0.6,
            'response_timeout': 30,
            'max_concurrent_responses': 5
        }
        
        # Active responses tracking
        self.active_responses = {}
        self.response_history = deque(maxlen=500)
        
        # Statistics
        self.coordination_stats = {
            'threats_processed': 0,
            'responses_initiated': 0,
            'correlations_found': 0,
            'false_positives': 0
        }
        
        logger.info("Coordination Agent initialized")

    def register_agent(self, agent: BaseSecurityAgent):
        """Register a managed agent"""
        self.managed_agents[agent.agent_id] = agent
        self.agent_status[agent.agent_id] = {
            'status': AgentStatus.IDLE,
            'last_heartbeat': time.time(),
            'message_count': 0
        }
        
        logger.info(f"Registered agent: {agent.agent_id} ({agent.agent_type})")

    def _do_work(self):
        """Main coordination work"""
        try:
            # Monitor agent health
            self._monitor_agent_health()
            
            # Process pending responses
            self._process_pending_responses()
            
            # Generate status reports
            if time.time() % 60 < 1:  # Every minute
                self._generate_status_report()
        
        except Exception as e:
            logger.error(f"Coordination error: {e}")

    def handle_custom_message(self, message: AgentMessage):
        """Handle coordination-specific messages"""
        if message.message_type == MessageType.THREAT_DETECTED:
            self._handle_threat_detection(message)
        elif message.message_type == MessageType.STATUS_UPDATE:
            self._handle_agent_status_update(message)
        elif message.message_type == MessageType.RESPONSE_ACTION:
            self._handle_response_completion(message)

    def _handle_threat_detection(self, message: AgentMessage):
        """Handle threat detection from specialized agents"""
        threat_data = message.payload
        
        # Correlate with existing threats
        correlation_result = self.correlation_engine.correlate_threats(threat_data)
        
        # Update statistics
        self.coordination_stats['threats_processed'] += 1
        if correlation_result['is_correlated']:
            self.coordination_stats['correlations_found'] += 1
        
        # Make response decision
        response_decision = self._make_response_decision(correlation_result)
        
        # Execute response
        if response_decision['should_respond']:
            self._initiate_response(correlation_result, response_decision)
        
        # Log threat
        logger.info(f"Threat processed from {message.sender_id}: {threat_data.get('threat_type')} "
                   f"(final confidence: {correlation_result['final_confidence']:.2f})")

    def _make_response_decision(self, correlation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Make intelligent response decision based on threat analysis"""
        final_confidence = correlation_result['final_confidence']
        final_severity = correlation_result['final_severity']
        threat_type = correlation_result['original_threat'].get('threat_type')
        
        # Determine response type
        if final_confidence >= self.decision_config['auto_response_threshold']:
            response_type = 'automatic'
            should_respond = True
        elif final_confidence >= self.decision_config['human_approval_threshold']:
            response_type = 'human_approval'
            should_respond = True
        else:
            response_type = 'monitor_only'
            should_respond = False
        
        # Determine response actions
        actions = []
        if should_respond:
            if threat_type == 'dos':
                actions = ['block_ip', 'rate_limit', 'alert_admin']
            elif threat_type == 'port_scan':
                actions = ['monitor_ip', 'log_activity', 'alert_security']
            elif threat_type == 'malware':
                actions = ['quarantine', 'scan_system', 'alert_critical']
            elif threat_type == 'phishing':
                actions = ['block_url', 'warn_users', 'alert_admin']
        
        return {
            'should_respond': should_respond,
            'response_type': response_type,
            'actions': actions,
            'priority': self._calculate_response_priority(final_severity, final_confidence),
            'estimated_duration': self._estimate_response_duration(actions)
        }

    def _initiate_response(self, correlation_result: Dict[str, Any], response_decision: Dict[str, Any]):
        """Initiate coordinated response to threat"""
        response_id = f"response_{int(time.time())}_{len(self.active_responses)}"
        
        response_data = {
            'response_id': response_id,
            'threat_data': correlation_result,
            'decision': response_decision,
            'start_time': time.time(),
            'status': 'initiated',
            'actions_completed': [],
            'actions_pending': response_decision['actions'].copy()
        }
        
        self.active_responses[response_id] = response_data
        
        # Send response messages to appropriate agents
        for action in response_decision['actions']:
            target_agent = self._get_response_agent(action)
            if target_agent:
                response_message = AgentMessage(
                    sender_id=self.agent_id,
                    receiver_id=target_agent,
                    message_type=MessageType.RESPONSE_ACTION,
                    payload={
                        'response_id': response_id,
                        'action': action,
                        'threat_data': correlation_result['original_threat'],
                        'priority': response_decision['priority']
                    },
                    timestamp=time.time(),
                    priority=response_decision['priority']
                )
                
                self.send_message(response_message)
        
        self.coordination_stats['responses_initiated'] += 1
        
        logger.info(f"Response initiated: {response_id} with actions: {response_decision['actions']}")

    def _get_response_agent(self, action: str) -> Optional[str]:
        """Get the appropriate agent for a response action"""
        action_agent_mapping = {
            'block_ip': 'response_agent',
            'rate_limit': 'response_agent',
            'quarantine': 'response_agent',
            'block_url': 'response_agent',
            'alert_admin': 'alert_agent',
            'alert_security': 'alert_agent',
            'alert_critical': 'alert_agent',
            'monitor_ip': 'monitoring_agent',
            'log_activity': 'logging_agent',
            'scan_system': 'scanner_agent'
        }
        
        return action_agent_mapping.get(action)

    def _calculate_response_priority(self, severity: str, confidence: float) -> int:
        """Calculate response priority (1-4, 4 being highest)"""
        base_priority = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }.get(severity, 1)
        
        # Boost priority for high confidence
        if confidence > 0.9:
            base_priority = min(4, base_priority + 1)
        
        return base_priority

    def _estimate_response_duration(self, actions: List[str]) -> int:
        """Estimate response duration in seconds"""
        action_durations = {
            'block_ip': 5,
            'rate_limit': 10,
            'quarantine': 30,
            'block_url': 5,
            'alert_admin': 2,
            'monitor_ip': 1,
            'log_activity': 1,
            'scan_system': 60
        }
        
        return sum(action_durations.get(action, 10) for action in actions)

    def _monitor_agent_health(self):
        """Monitor health of all managed agents"""
        current_time = time.time()
        
        for agent_id, status_info in self.agent_status.items():
            # Check for stale heartbeats
            if current_time - status_info['last_heartbeat'] > 60:  # 1 minute timeout
                logger.warning(f"Agent {agent_id} heartbeat timeout")
                status_info['status'] = AgentStatus.ERROR
            
            # Request status updates periodically
            if current_time % 30 < 1:  # Every 30 seconds
                status_request = AgentMessage(
                    sender_id=self.agent_id,
                    receiver_id=agent_id,
                    message_type=MessageType.STATUS_UPDATE,
                    payload={'request_type': 'status_report'},
                    timestamp=current_time,
                    priority=1
                )
                self.send_message(status_request)

    def _process_pending_responses(self):
        """Process and monitor active responses"""
        current_time = time.time()
        completed_responses = []
        
        for response_id, response_data in self.active_responses.items():
            # Check for timeout
            if current_time - response_data['start_time'] > self.decision_config['response_timeout']:
                logger.warning(f"Response {response_id} timed out")
                response_data['status'] = 'timeout'
                completed_responses.append(response_id)
            
            # Check if all actions completed
            elif not response_data['actions_pending']:
                response_data['status'] = 'completed'
                response_data['end_time'] = current_time
                completed_responses.append(response_id)
        
        # Move completed responses to history
        for response_id in completed_responses:
            response_data = self.active_responses.pop(response_id)
            self.response_history.append(response_data)

    def _handle_response_completion(self, message: AgentMessage):
        """Handle response completion from response agents"""
        payload = message.payload
        response_id = payload.get('response_id')
        completed_action = payload.get('completed_action')
        success = payload.get('success', False)
        
        if response_id in self.active_responses:
            response_data = self.active_responses[response_id]
            
            if completed_action in response_data['actions_pending']:
                response_data['actions_pending'].remove(completed_action)
                response_data['actions_completed'].append({
                    'action': completed_action,
                    'success': success,
                    'timestamp': time.time(),
                    'agent': message.sender_id
                })
                
                logger.info(f"Response action completed: {completed_action} (success: {success})")

    def _generate_status_report(self):
        """Generate comprehensive status report"""
        current_time = time.time()
        uptime = current_time - self.stats['start_time']
        
        status_report = {
            'coordinator_status': {
                'uptime': uptime,
                'active_responses': len(self.active_responses),
                'managed_agents': len(self.managed_agents),
                'coordination_stats': self.coordination_stats.copy()
            },
            'agent_status': {
                agent_id: {
                    'status': status_info['status'].value if hasattr(status_info['status'], 'value') else str(status_info['status']),
                    'last_heartbeat': current_time - status_info['last_heartbeat'],
                    'message_count': status_info['message_count']
                }
                for agent_id, status_info in self.agent_status.items()
            },
            'recent_threats': list(self.correlation_engine.threat_history)[-10:],
            'active_responses': list(self.active_responses.keys())
        }
        
        logger.debug(f"Status report generated: {len(self.managed_agents)} agents, "
                    f"{len(self.active_responses)} active responses")
        
        return status_report

    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive system status for dashboard"""
        return self._generate_status_report()
