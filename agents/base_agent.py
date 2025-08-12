"""
Base Agent Class for Multi-Agent Cybersecurity Architecture
Professional foundation for specialized security agents
"""

import threading
import queue
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json

logger = logging.getLogger(__name__)

class AgentStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    ERROR = "error"
    SHUTDOWN = "shutdown"

class MessageType(Enum):
    THREAT_DETECTED = "threat_detected"
    ANALYSIS_REQUEST = "analysis_request"
    RESPONSE_ACTION = "response_action"
    STATUS_UPDATE = "status_update"
    COORDINATION = "coordination"
    LEARNING_UPDATE = "learning_update"

@dataclass
class AgentMessage:
    """Standard message format for inter-agent communication"""
    sender_id: str
    receiver_id: str
    message_type: MessageType
    payload: Dict[str, Any]
    timestamp: float
    priority: int = 1  # 1=low, 2=medium, 3=high, 4=critical
    correlation_id: Optional[str] = None

class BaseSecurityAgent(ABC):
    """
    Abstract base class for all cybersecurity agents
    Provides common functionality and communication protocols
    """
    
    def __init__(self, agent_id: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = AgentStatus.IDLE
        self.message_queue = queue.PriorityQueue()
        self.outbound_queue = queue.Queue()
        
        # Agent statistics
        self.stats = {
            'messages_processed': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'start_time': time.time(),
            'last_activity': time.time()
        }
        
        # Threading
        self.running = False
        self.worker_thread = None
        self.message_thread = None
        
        # Configuration
        self.config = {
            'max_queue_size': 1000,
            'processing_timeout': 30,
            'heartbeat_interval': 10
        }
        
        logger.info(f"Initialized {self.agent_type} agent: {self.agent_id}")

    def start(self):
        """Start the agent's processing threads"""
        if self.running:
            logger.warning(f"Agent {self.agent_id} already running")
            return
        
        self.running = True
        self.status = AgentStatus.ACTIVE
        
        # Start message processing thread
        self.message_thread = threading.Thread(target=self._message_loop, daemon=True)
        self.message_thread.start()
        
        # Start main worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
        logger.info(f"Agent {self.agent_id} started")

    def stop(self):
        """Stop the agent gracefully"""
        self.running = False
        self.status = AgentStatus.SHUTDOWN
        
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        if self.message_thread:
            self.message_thread.join(timeout=5)
        
        logger.info(f"Agent {self.agent_id} stopped")

    def send_message(self, message: AgentMessage):
        """Send message to another agent"""
        try:
            self.outbound_queue.put(message, timeout=1)
        except queue.Full:
            logger.error(f"Outbound queue full for agent {self.agent_id}")

    def receive_message(self, message: AgentMessage):
        """Receive message from another agent"""
        try:
            # Priority queue: (priority, timestamp, message)
            priority_item = (-message.priority, message.timestamp, message)
            self.message_queue.put(priority_item, timeout=1)
        except queue.Full:
            logger.error(f"Message queue full for agent {self.agent_id}")

    def _message_loop(self):
        """Main message processing loop"""
        while self.running:
            try:
                # Get message with timeout
                priority_item = self.message_queue.get(timeout=1)
                _, _, message = priority_item
                
                # Process message
                self._process_message(message)
                self.stats['messages_processed'] += 1
                self.stats['last_activity'] = time.time()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Message processing error in {self.agent_id}: {e}")

    def _worker_loop(self):
        """Main worker loop - implemented by subclasses"""
        while self.running:
            try:
                self._do_work()
                time.sleep(0.1)  # Prevent busy waiting
            except Exception as e:
                logger.error(f"Worker error in {self.agent_id}: {e}")
                self.status = AgentStatus.ERROR
                time.sleep(1)

    def _process_message(self, message: AgentMessage):
        """Process incoming message - can be overridden by subclasses"""
        if message.message_type == MessageType.STATUS_UPDATE:
            self._handle_status_update(message)
        elif message.message_type == MessageType.THREAT_DETECTED:
            self._handle_threat_detection(message)
        elif message.message_type == MessageType.ANALYSIS_REQUEST:
            self._handle_analysis_request(message)
        else:
            self.handle_custom_message(message)

    @abstractmethod
    def _do_work(self):
        """Main work function - must be implemented by subclasses"""
        pass

    @abstractmethod
    def handle_custom_message(self, message: AgentMessage):
        """Handle custom message types - must be implemented by subclasses"""
        pass

    def _handle_status_update(self, message: AgentMessage):
        """Handle status update messages"""
        logger.debug(f"Agent {self.agent_id} received status update from {message.sender_id}")

    def _handle_threat_detection(self, message: AgentMessage):
        """Handle threat detection messages"""
        logger.info(f"Agent {self.agent_id} received threat detection from {message.sender_id}")

    def _handle_analysis_request(self, message: AgentMessage):
        """Handle analysis request messages"""
        logger.debug(f"Agent {self.agent_id} received analysis request from {message.sender_id}")

    def get_status(self) -> Dict[str, Any]:
        """Get agent status and statistics"""
        uptime = time.time() - self.stats['start_time']
        
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type,
            'status': self.status.value,
            'uptime': uptime,
            'queue_size': self.message_queue.qsize(),
            'stats': self.stats.copy(),
            'config': self.config.copy()
        }

    def update_config(self, new_config: Dict[str, Any]):
        """Update agent configuration"""
        self.config.update(new_config)
        logger.info(f"Agent {self.agent_id} configuration updated")
