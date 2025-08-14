"""
Phase 2: Reinforcement Learning Engine for Cybersecurity Response
Implements Q-learning and policy-based decisions for threat response
"""

import numpy as np
import json
import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import uuid
from collections import defaultdict, deque
import random

logger = logging.getLogger(__name__)

class CybersecurityRLEngine:
    """
    Reinforcement Learning engine for cybersecurity response decisions
    Learns optimal actions (block, allow, observe) based on threat scenarios
    """
    
    def __init__(self, model_dir: str = "/app/models/rl"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        # RL Components
        self.q_tables = {}  # Q-tables for different policies
        self.policies = {}  # Policy metadata
        self.experience_buffer = deque(maxlen=10000)  # Experience replay
        
        # RL Parameters
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.epsilon = 0.1  # Exploration rate
        
        # Action space
        self.actions = ['block', 'allow', 'observe', 'escalate']
        self.action_to_index = {action: i for i, action in enumerate(self.actions)}
        
        # State features (discretized for Q-learning)
        self.state_bins = {
            'threat_score': np.linspace(0, 1, 10),
            'severity_level': ['low', 'medium', 'high', 'critical'],
            'source_trust': np.linspace(0, 1, 5),
            'time_of_day': np.arange(0, 24, 4),  # 6 time periods
            'system_load': np.linspace(0, 1, 5)
        }
        
        logger.info("RL Engine initialized")
    
    def discretize_state(self, state: Dict[str, Any]) -> Tuple[int, ...]:
        """
        Convert continuous state to discrete state for Q-learning
        """
        discrete_state = []
        
        # Threat score (0-1)
        threat_score = state.get('threat_score', 0.5)
        threat_bin = np.digitize(threat_score, self.state_bins['threat_score']) - 1
        discrete_state.append(max(0, min(9, threat_bin)))
        
        # Severity level
        severity = state.get('severity', 'medium')
        severity_index = self.state_bins['severity_level'].index(severity) if severity in self.state_bins['severity_level'] else 1
        discrete_state.append(severity_index)
        
        # Source trust (0-1, higher = more trusted)
        source_trust = state.get('source_trust', 0.5)
        trust_bin = np.digitize(source_trust, self.state_bins['source_trust']) - 1
        discrete_state.append(max(0, min(4, trust_bin)))
        
        # Time of day
        hour = datetime.now().hour
        time_bin = hour // 4
        discrete_state.append(time_bin)
        
        # System load (0-1)
        system_load = state.get('system_load', 0.5)
        load_bin = np.digitize(system_load, self.state_bins['system_load']) - 1
        discrete_state.append(max(0, min(4, load_bin)))
        
        return tuple(discrete_state)
    
    def calculate_reward(self, state: Dict[str, Any], action: str, outcome: Dict[str, Any]) -> float:
        """
        Calculate reward based on action outcome
        """
        base_reward = 0.0
        threat_score = state.get('threat_score', 0.5)
        
        # Outcome-based rewards
        if outcome.get('false_positive', False):
            base_reward -= 10.0  # Penalty for false positives
        elif outcome.get('true_positive', False):
            base_reward += 20.0  # Reward for correct detection
        elif outcome.get('false_negative', False):
            base_reward -= 30.0  # Heavy penalty for missed threats
        elif outcome.get('true_negative', False):
            base_reward += 10.0  # Moderate reward for correct rejection
        
        # Action-specific rewards
        if action == 'block':
            if threat_score > 0.7:
                base_reward += 5.0  # Good decision to block high-threat
            elif threat_score < 0.3:
                base_reward -= 5.0  # Potentially unnecessary block
        
        elif action == 'allow':
            if threat_score < 0.3:
                base_reward += 3.0  # Good decision to allow low-threat
            elif threat_score > 0.7:
                base_reward -= 15.0  # Risky decision to allow high-threat
        
        elif action == 'observe':
            base_reward += 1.0  # Small reward for gathering intelligence
            if threat_score > 0.8:
                base_reward -= 5.0  # Should have acted on critical threat
        
        elif action == 'escalate':
            if threat_score > 0.6:
                base_reward += 8.0  # Good decision to escalate
            else:
                base_reward -= 2.0  # Unnecessary escalation
        
        # Time-based penalty (encourage quick decisions)
        response_time = outcome.get('response_time_seconds', 5)
        if response_time > 10:
            base_reward -= 1.0
        
        # System impact consideration
        system_impact = outcome.get('system_impact', 0.5)  # 0=no impact, 1=severe impact
        base_reward -= system_impact * 5.0
        
        return base_reward
    
    def train_policy(self, 
                    policy_name: str,
                    training_episodes: List[Dict[str, Any]],
                    episodes: int = 1000) -> Dict[str, Any]:
        """
        Train RL policy using Q-learning
        """
        logger.info(f"Training policy '{policy_name}' for {episodes} episodes")
        
        # Initialize Q-table
        q_table = defaultdict(lambda: np.zeros(len(self.actions)))
        
        # Training statistics
        stats = {
            'total_reward': 0,
            'episodes_completed': 0,
            'actions_taken': defaultdict(int),
            'average_reward': 0
        }
        
        for episode in range(episodes):
            # Sample training episode (or use provided episodes)
            if training_episodes:
                episode_data = random.choice(training_episodes)
            else:
                episode_data = self._generate_synthetic_episode()
            
            state = episode_data['state']
            discrete_state = self.discretize_state(state)
            
            # Epsilon-greedy action selection
            if random.random() < self.epsilon:
                action_index = random.randint(0, len(self.actions) - 1)
            else:
                action_index = np.argmax(q_table[discrete_state])
            
            action = self.actions[action_index]
            
            # Get outcome (from episode data or simulate)
            outcome = episode_data.get('outcome', self._simulate_outcome(state, action))
            
            # Calculate reward
            reward = self.calculate_reward(state, action, outcome)
            
            # Get next state (simplified - assume terminal state for now)
            next_state = episode_data.get('next_state', state)
            next_discrete_state = self.discretize_state(next_state)
            
            # Q-learning update
            current_q = q_table[discrete_state][action_index]
            max_next_q = np.max(q_table[next_discrete_state])
            
            new_q = current_q + self.learning_rate * (
                reward + self.discount_factor * max_next_q - current_q
            )
            
            q_table[discrete_state][action_index] = new_q
            
            # Update statistics
            stats['total_reward'] += reward
            stats['actions_taken'][action] += 1
            
            if episode % 100 == 0:
                logger.debug(f"Episode {episode}, Reward: {reward:.2f}, Action: {action}")
        
        # Finalize training
        stats['episodes_completed'] = episodes
        stats['average_reward'] = stats['total_reward'] / episodes
        
        # Store policy
        policy_id = str(uuid.uuid4())
        self.q_tables[policy_id] = dict(q_table)  # Convert defaultdict to dict
        
        self.policies[policy_id] = {
            'name': policy_name,
            'trained_at': datetime.now().isoformat(),
            'episodes': episodes,
            'learning_rate': self.learning_rate,
            'discount_factor': self.discount_factor,
            'epsilon': self.epsilon,
            'stats': stats,
            'version': '1.0'
        }
        
        # Save to disk
        self._save_policy(policy_id)
        
        logger.info(f"Policy '{policy_name}' trained successfully. Average reward: {stats['average_reward']:.2f}")
        
        return {
            'policy_id': policy_id,
            'name': policy_name,
            'episodes': episodes,
            'average_reward': stats['average_reward'],
            'status': 'trained'
        }
    
    def suggest_action(self, 
                      state: Dict[str, Any], 
                      policy_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Suggest optimal action for given state
        """
        if not self.q_tables:
            # Fallback to rule-based if no trained policies
            return self._rule_based_action(state)
        
        # Use latest policy if not specified
        if policy_id is None:
            policy_id = max(self.policies.keys(), 
                          key=lambda k: self.policies[k]['trained_at'])
        
        if policy_id not in self.q_tables:
            raise ValueError(f"Policy {policy_id} not found")
        
        q_table = self.q_tables[policy_id]
        discrete_state = self.discretize_state(state)
        
        # Get Q-values for current state
        if discrete_state in q_table:
            q_values = q_table[discrete_state]
            action_index = np.argmax(q_values)
            confidence = np.max(q_values) / (np.sum(np.abs(q_values)) + 1e-8)
        else:
            # Unknown state - use exploration
            action_index = random.randint(0, len(self.actions) - 1)
            confidence = 0.0
            q_values = np.zeros(len(self.actions))
        
        suggested_action = self.actions[action_index]
        
        # Generate action probabilities
        softmax_q = self._softmax(q_values)
        action_probabilities = {
            action: float(prob) 
            for action, prob in zip(self.actions, softmax_q)
        }
        
        return {
            'policy_id': policy_id,
            'suggested_action': suggested_action,
            'confidence': float(confidence),
            'action_probabilities': action_probabilities,
            'q_values': [float(x) for x in q_values],
            'state_representation': [int(x) for x in discrete_state],
            'timestamp': datetime.now().isoformat()
        }
    
    def _rule_based_action(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback rule-based action selection
        """
        threat_score = state.get('threat_score', 0.5)
        severity = state.get('severity', 'medium')
        
        if threat_score > 0.8 or severity == 'critical':
            action = 'block'
            confidence = 0.9
        elif threat_score > 0.6 or severity == 'high':
            action = 'escalate'
            confidence = 0.7
        elif threat_score > 0.4 or severity == 'medium':
            action = 'observe'
            confidence = 0.6
        else:
            action = 'allow'
            confidence = 0.8
        
        return {
            'policy_id': 'rule_based',
            'suggested_action': action,
            'confidence': confidence,
            'action_probabilities': {action: confidence},
            'fallback': True,
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_synthetic_episode(self) -> Dict[str, Any]:
        """
        Generate synthetic training episode
        """
        state = {
            'threat_score': random.random(),
            'severity': random.choice(self.state_bins['severity_level']),
            'source_trust': random.random(),
            'system_load': random.random()
        }
        
        # Simulate outcome based on state
        threat_score = state['threat_score']
        outcome = {
            'true_positive': threat_score > 0.7 and random.random() < 0.8,
            'false_positive': threat_score < 0.3 and random.random() < 0.2,
            'response_time_seconds': random.randint(1, 10),
            'system_impact': random.random() * 0.5
        }
        
        return {
            'state': state,
            'outcome': outcome,
            'next_state': state  # Simplified
        }
    
    def _simulate_outcome(self, state: Dict[str, Any], action: str) -> Dict[str, Any]:
        """
        Simulate outcome for state-action pair
        """
        threat_score = state.get('threat_score', 0.5)
        
        # Realistic outcome simulation
        if action == 'block':
            if threat_score > 0.7:
                return {'true_positive': True, 'response_time_seconds': 2}
            else:
                return {'false_positive': True, 'response_time_seconds': 2}
        
        elif action == 'allow':
            if threat_score < 0.3:
                return {'true_negative': True, 'response_time_seconds': 1}
            else:
                return {'false_negative': True, 'response_time_seconds': 1}
        
        return {'response_time_seconds': 5, 'system_impact': 0.1}
    
    def _softmax(self, x: np.ndarray, temperature: float = 1.0) -> np.ndarray:
        """
        Compute softmax probabilities
        """
        exp_x = np.exp((x - np.max(x)) / temperature)
        return exp_x / np.sum(exp_x)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get RL engine status
        """
        return {
            'installed': True,
            'has_policies': len(self.policies) > 0,
            'policy_count': len(self.policies),
            'policies': [
                {
                    'id': policy_id,
                    'name': metadata['name'],
                    'trained_at': metadata['trained_at'],
                    'episodes': metadata['episodes'],
                    'average_reward': metadata['stats']['average_reward'],
                    'version': metadata['version']
                }
                for policy_id, metadata in self.policies.items()
            ],
            'actions': self.actions,
            'learning_rate': self.learning_rate,
            'discount_factor': self.discount_factor
        }
    
    def _save_policy(self, policy_id: str):
        """Save policy to disk"""
        policy_path = os.path.join(self.model_dir, f"policy_{policy_id}.json")
        qtable_path = os.path.join(self.model_dir, f"qtable_{policy_id}.json")
        
        # Save policy metadata
        with open(policy_path, 'w') as f:
            json.dump(self.policies[policy_id], f, indent=2)
        
        # Save Q-table (convert numpy arrays to lists)
        q_table_serializable = {}
        for state, q_values in self.q_tables[policy_id].items():
            q_table_serializable[str(state)] = q_values.tolist() if hasattr(q_values, 'tolist') else list(q_values)
        
        with open(qtable_path, 'w') as f:
            json.dump(q_table_serializable, f, indent=2)
    
    def load_policies(self) -> int:
        """Load saved policies from disk"""
        loaded_count = 0
        
        if not os.path.exists(self.model_dir):
            return loaded_count
        
        for filename in os.listdir(self.model_dir):
            if filename.startswith('policy_') and filename.endswith('.json'):
                policy_id = filename.replace('policy_', '').replace('.json', '')
                
                try:
                    # Load policy metadata
                    with open(os.path.join(self.model_dir, filename), 'r') as f:
                        self.policies[policy_id] = json.load(f)
                    
                    # Load Q-table
                    qtable_path = os.path.join(self.model_dir, f"qtable_{policy_id}.json")
                    if os.path.exists(qtable_path):
                        with open(qtable_path, 'r') as f:
                            q_table_data = json.load(f)
                        
                        # Convert back to proper format
                        q_table = {}
                        for state_str, q_values in q_table_data.items():
                            state = eval(state_str)  # Convert string back to tuple
                            q_table[state] = np.array(q_values)
                        
                        self.q_tables[policy_id] = q_table
                        loaded_count += 1
                        logger.info(f"Loaded RL policy {policy_id}")
                
                except Exception as e:
                    logger.error(f"Error loading policy {policy_id}: {e}")
        
        return loaded_count

# Global instance
rl_engine = CybersecurityRLEngine()
rl_engine.load_policies()