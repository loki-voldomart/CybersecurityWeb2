#!/usr/bin/env python3
"""
Comprehensive Backend Testing for AI/ML Cybersecurity Suite
Tests all three phases: Anomaly Detection, Reinforcement Learning, and AI Analysis
"""

import requests
import json
import time
import sys
from typing import Dict, List, Any
from datetime import datetime

class CybersecurityAPITester:
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'CybersecurityTester/1.0'
        })
        self.test_results = []
        
    def log_result(self, test_name: str, success: bool, details: str, response_data: Any = None):
        """Log test result"""
        result = {
            'test': test_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'response_data': response_data
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {details}")
        
    def make_request(self, method: str, endpoint: str, data: Dict = None) -> tuple:
        """Make HTTP request and return response and success status"""
        url = f"{self.base_url}{endpoint}"
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=30)
            else:
                return None, False, f"Unsupported method: {method}"
            
            return response, True, None
        except requests.exceptions.RequestException as e:
            return None, False, str(e)
    
    def generate_network_telemetry(self, anomalous: bool = False) -> Dict[str, Any]:
        """Generate realistic network telemetry data"""
        if anomalous:
            # Suspicious network activity
            return {
                "packet_size": 65535,  # Maximum packet size - suspicious
                "duration": 0.001,     # Very short duration
                "bytes_sent": 1048576, # 1MB sent quickly
                "bytes_received": 0,   # No response - potential DoS
                "protocol": "TCP",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "port": 22,           # SSH port
                "metadata": {
                    "connection_count": 1000,  # High connection count
                    "error_rate": 0.8,         # High error rate
                    "retry_count": 50,         # Many retries
                    "flags": ["SYN", "FIN", "RST"]  # Suspicious flag combination
                }
            }
        else:
            # Normal network activity
            return {
                "packet_size": 1500,   # Standard MTU
                "duration": 0.5,       # Normal duration
                "bytes_sent": 2048,    # Normal data size
                "bytes_received": 1024,
                "protocol": "HTTPS",
                "source_ip": "192.168.1.50",
                "destination_ip": "8.8.8.8",
                "port": 443,          # HTTPS port
                "metadata": {
                    "connection_count": 5,
                    "error_rate": 0.01,
                    "retry_count": 0,
                    "flags": ["ACK"]
                }
            }
    
    def generate_threat_scenario(self, threat_type: str = "port_scan") -> Dict[str, Any]:
        """Generate realistic threat scenario data"""
        scenarios = {
            "port_scan": {
                "threat_type": "Port Scan Attack",
                "severity": "medium",
                "source_ip": "203.0.113.45",
                "target_ip": "192.168.1.10",
                "port": 80,
                "description": "Systematic port scanning detected from external IP attempting to identify open services",
                "detected_at": datetime.now().isoformat(),
                "status": "active",
                "metadata": {
                    "ports_scanned": [22, 23, 80, 443, 3389],
                    "scan_rate": "high",
                    "duration_seconds": 120
                }
            },
            "ddos_attack": {
                "threat_type": "DDoS Attack",
                "severity": "critical",
                "source_ip": "198.51.100.25",
                "target_ip": "192.168.1.5",
                "port": 80,
                "description": "Distributed Denial of Service attack detected with high volume traffic from multiple sources",
                "detected_at": datetime.now().isoformat(),
                "status": "active",
                "metadata": {
                    "request_rate": 10000,
                    "source_count": 50,
                    "attack_vector": "HTTP flood"
                }
            },
            "malware_communication": {
                "threat_type": "Malware C&C Communication",
                "severity": "high",
                "source_ip": "192.168.1.25",
                "target_ip": "185.159.158.234",
                "port": 8080,
                "description": "Suspected malware command and control communication detected",
                "detected_at": datetime.now().isoformat(),
                "status": "investigating",
                "metadata": {
                    "communication_pattern": "periodic",
                    "data_exfiltration": True,
                    "encryption": "custom"
                }
            }
        }
        return scenarios.get(threat_type, scenarios["port_scan"])
    
    def generate_rl_state(self, scenario: str = "normal") -> Dict[str, Any]:
        """Generate RL state data for different scenarios"""
        states = {
            "normal": {
                "threat_score": 0.2,
                "severity": "low",
                "source_trust": 0.8,
                "system_load": 0.3
            },
            "suspicious": {
                "threat_score": 0.6,
                "severity": "medium", 
                "source_trust": 0.4,
                "system_load": 0.7
            },
            "critical": {
                "threat_score": 0.9,
                "severity": "critical",
                "source_trust": 0.1,
                "system_load": 0.9
            }
        }
        return states.get(scenario, states["normal"])

    # PHASE 1: ANOMALY DETECTION TESTS
    
    def test_anomaly_status(self):
        """Test anomaly detection status endpoint"""
        response, success, error = self.make_request('GET', '/api/ml/anomaly/status')
        
        if not success:
            self.log_result("Anomaly Status", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'installed' in data:
                self.log_result("Anomaly Status", True, f"Status retrieved successfully. Has model: {data.get('has_model', False)}", data)
                return True
            else:
                self.log_result("Anomaly Status", False, "Invalid response format", data)
                return False
        else:
            self.log_result("Anomaly Status", False, f"HTTP {response.status_code}: {response.text}")
            return False
    
    def test_anomaly_training(self):
        """Test anomaly model training"""
        # Generate training samples (normal behavior)
        normal_samples = [self.generate_network_telemetry(anomalous=False) for _ in range(20)]
        
        # Test Isolation Forest
        training_data = {
            "algorithm": "isolation_forest",
            "samples": normal_samples,
            "contamination": 0.1
        }
        
        response, success, error = self.make_request('POST', '/api/ml/anomaly/train', training_data)
        
        if not success:
            self.log_result("Anomaly Training (Isolation Forest)", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'model_id' in data and data.get('status') == 'trained':
                self.log_result("Anomaly Training (Isolation Forest)", True, f"Model trained successfully. ID: {data['model_id']}", data)
                self.isolation_forest_model_id = data['model_id']
                
                # Test One-Class SVM
                training_data['algorithm'] = 'one_class_svm'
                training_data['nu'] = 0.05
                
                response2, success2, error2 = self.make_request('POST', '/api/ml/anomaly/train', training_data)
                
                if success2 and response2.status_code == 200:
                    data2 = response2.json()
                    if 'model_id' in data2:
                        self.log_result("Anomaly Training (One-Class SVM)", True, f"SVM model trained. ID: {data2['model_id']}", data2)
                        self.svm_model_id = data2['model_id']
                        return True
                    else:
                        self.log_result("Anomaly Training (One-Class SVM)", False, "Invalid SVM response", data2)
                        return False
                else:
                    self.log_result("Anomaly Training (One-Class SVM)", False, f"SVM training failed: {error2 if not success2 else response2.text}")
                    return False
            else:
                self.log_result("Anomaly Training (Isolation Forest)", False, "Training failed or invalid response", data)
                return False
        else:
            self.log_result("Anomaly Training (Isolation Forest)", False, f"HTTP {response.status_code}: {response.text}")
            return False
    
    def test_anomaly_prediction(self):
        """Test anomaly prediction"""
        # Test with normal telemetry
        normal_telemetry = self.generate_network_telemetry(anomalous=False)
        prediction_data = {"telemetry": normal_telemetry}
        
        response, success, error = self.make_request('POST', '/api/ml/anomaly/predict', prediction_data)
        
        if not success:
            self.log_result("Anomaly Prediction (Normal)", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'is_anomaly' in data and 'score' in data:
                self.log_result("Anomaly Prediction (Normal)", True, f"Normal traffic prediction: anomaly={data['is_anomaly']}, score={data['score']:.3f}", data)
                
                # Test with anomalous telemetry
                anomalous_telemetry = self.generate_network_telemetry(anomalous=True)
                prediction_data = {"telemetry": anomalous_telemetry}
                
                response2, success2, error2 = self.make_request('POST', '/api/ml/anomaly/predict', prediction_data)
                
                if success2 and response2.status_code == 200:
                    data2 = response2.json()
                    if 'is_anomaly' in data2:
                        self.log_result("Anomaly Prediction (Anomalous)", True, f"Anomalous traffic prediction: anomaly={data2['is_anomaly']}, score={data2['score']:.3f}", data2)
                        return True
                    else:
                        self.log_result("Anomaly Prediction (Anomalous)", False, "Invalid anomalous prediction response", data2)
                        return False
                else:
                    self.log_result("Anomaly Prediction (Anomalous)", False, f"Anomalous prediction failed: {error2 if not success2 else response2.text}")
                    return False
            else:
                self.log_result("Anomaly Prediction (Normal)", False, "Invalid prediction response format", data)
                return False
        else:
            self.log_result("Anomaly Prediction (Normal)", False, f"HTTP {response.status_code}: {response.text}")
            return False

    # PHASE 2: REINFORCEMENT LEARNING TESTS
    
    def test_rl_status(self):
        """Test RL engine status endpoint"""
        response, success, error = self.make_request('GET', '/api/rl/policy/status')
        
        if not success:
            self.log_result("RL Status", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'installed' in data:
                self.log_result("RL Status", True, f"RL status retrieved. Has policies: {data.get('has_policies', False)}", data)
                return True
            else:
                self.log_result("RL Status", False, "Invalid RL status response", data)
                return False
        else:
            self.log_result("RL Status", False, f"HTTP {response.status_code}: {response.text}")
            return False
    
    def test_rl_training(self):
        """Test RL policy training"""
        # Generate training episodes
        training_episodes = []
        for i in range(10):
            episode = {
                "state": self.generate_rl_state("suspicious" if i % 3 == 0 else "normal"),
                "outcome": {
                    "true_positive": i % 4 == 0,
                    "false_positive": i % 7 == 0,
                    "response_time_seconds": 2 + (i % 5),
                    "system_impact": 0.1 * (i % 3)
                }
            }
            training_episodes.append(episode)
        
        training_data = {
            "policy_name": "cybersecurity_response_policy",
            "training_episodes": training_episodes,
            "episodes": 500
        }
        
        response, success, error = self.make_request('POST', '/api/rl/policy/train', training_data)
        
        if not success:
            self.log_result("RL Policy Training", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'policy_id' in data and data.get('status') == 'trained':
                self.log_result("RL Policy Training", True, f"Policy trained successfully. ID: {data['policy_id']}, Avg Reward: {data.get('average_reward', 0):.3f}", data)
                self.policy_id = data['policy_id']
                return True
            else:
                self.log_result("RL Policy Training", False, "Training failed or invalid response", data)
                return False
        else:
            self.log_result("RL Policy Training", False, f"HTTP {response.status_code}: {response.text}")
            return False
    
    def test_rl_action_suggestion(self):
        """Test RL action suggestion for different scenarios"""
        scenarios = ["normal", "suspicious", "critical"]
        all_passed = True
        
        for scenario in scenarios:
            state = self.generate_rl_state(scenario)
            request_data = {"state": state}
            
            response, success, error = self.make_request('POST', '/api/rl/policy/suggest-action', request_data)
            
            if not success:
                self.log_result(f"RL Action Suggestion ({scenario})", False, f"Request failed: {error}")
                all_passed = False
                continue
                
            if response.status_code == 200:
                data = response.json()
                if 'suggested_action' in data and 'confidence' in data:
                    action = data['suggested_action']
                    confidence = data['confidence']
                    self.log_result(f"RL Action Suggestion ({scenario})", True, f"Action: {action}, Confidence: {confidence:.3f}", data)
                    
                    # Validate action is in expected set
                    expected_actions = ['block', 'allow', 'observe', 'escalate']
                    if action not in expected_actions:
                        self.log_result(f"RL Action Validation ({scenario})", False, f"Invalid action: {action}")
                        all_passed = False
                else:
                    self.log_result(f"RL Action Suggestion ({scenario})", False, "Invalid response format", data)
                    all_passed = False
            else:
                self.log_result(f"RL Action Suggestion ({scenario})", False, f"HTTP {response.status_code}: {response.text}")
                all_passed = False
        
        return all_passed

    # PHASE 3: AI-POWERED ANALYSIS TESTS
    
    def test_ai_threat_analysis(self):
        """Test AI threat analysis with different scenarios and styles"""
        threat_scenarios = ["port_scan", "ddos_attack", "malware_communication"]
        analysis_styles = ["concise", "detailed"]
        all_passed = True
        
        for threat_type in threat_scenarios:
            for style in analysis_styles:
                threat_data = self.generate_threat_scenario(threat_type)
                request_data = {
                    "threat_data": threat_data,
                    "analysis_style": style,
                    "analysis_type": "threat_analysis"
                }
                
                response, success, error = self.make_request('POST', '/api/ai/recommend', request_data)
                
                if not success:
                    self.log_result(f"AI Threat Analysis ({threat_type}, {style})", False, f"Request failed: {error}")
                    all_passed = False
                    continue
                    
                if response.status_code == 200:
                    data = response.json()
                    if 'ai_enabled' in data:
                        if data['ai_enabled']:
                            self.log_result(f"AI Threat Analysis ({threat_type}, {style})", True, f"AI analysis completed successfully", data)
                        else:
                            # AI not available, but fallback should work
                            if 'fallback_analysis' in data:
                                self.log_result(f"AI Threat Analysis ({threat_type}, {style})", True, f"Fallback analysis provided (AI unavailable)", data)
                            else:
                                self.log_result(f"AI Threat Analysis ({threat_type}, {style})", False, "No analysis provided", data)
                                all_passed = False
                    else:
                        self.log_result(f"AI Threat Analysis ({threat_type}, {style})", False, "Invalid response format", data)
                        all_passed = False
                else:
                    self.log_result(f"AI Threat Analysis ({threat_type}, {style})", False, f"HTTP {response.status_code}: {response.text}")
                    all_passed = False
        
        return all_passed
    
    def test_ai_remediation(self):
        """Test AI remediation recommendations"""
        incident_data = self.generate_threat_scenario("ddos_attack")
        incident_data["id"] = "incident_001"
        incident_data["actions_taken"] = ["blocked_source_ip", "increased_rate_limiting"]
        
        request_data = {
            "threat_data": incident_data,
            "analysis_type": "remediation"
        }
        
        response, success, error = self.make_request('POST', '/api/ai/recommend', request_data)
        
        if not success:
            self.log_result("AI Remediation", False, f"Request failed: {error}")
            return False
            
        if response.status_code == 200:
            data = response.json()
            if 'ai_enabled' in data:
                if data['ai_enabled'] and 'analysis' in data:
                    self.log_result("AI Remediation", True, "AI remediation recommendations generated", data)
                    return True
                elif not data['ai_enabled'] and 'fallback_analysis' in data:
                    self.log_result("AI Remediation", True, "Fallback remediation provided (AI unavailable)", data)
                    return True
                else:
                    self.log_result("AI Remediation", False, "No remediation provided", data)
                    return False
            else:
                self.log_result("AI Remediation", False, "Invalid response format", data)
                return False
        else:
            self.log_result("AI Remediation", False, f"HTTP {response.status_code}: {response.text}")
            return False
    
    def test_ai_consultation(self):
        """Test AI security consultation"""
        consultation_queries = [
            {
                "query": "How can we improve our network security posture against DDoS attacks?",
                "context": {"current_defenses": ["firewall", "rate_limiting"], "recent_attacks": 3}
            },
            {
                "query": "What are the best practices for incident response in a cloud environment?",
                "context": {"environment": "AWS", "team_size": 5}
            },
            {
                "query": "How should we handle a suspected data breach?",
                "context": {"data_types": ["customer_info", "financial_records"], "compliance": ["GDPR", "PCI-DSS"]}
            }
        ]
        
        all_passed = True
        
        for i, consultation in enumerate(consultation_queries):
            response, success, error = self.make_request('POST', '/api/ai/consult', consultation)
            
            if not success:
                self.log_result(f"AI Consultation {i+1}", False, f"Request failed: {error}")
                all_passed = False
                continue
                
            if response.status_code == 200:
                data = response.json()
                if 'ai_enabled' in data and 'response' in data:
                    if data['ai_enabled']:
                        self.log_result(f"AI Consultation {i+1}", True, "AI consultation completed", data)
                    else:
                        self.log_result(f"AI Consultation {i+1}", True, "Consultation response provided (AI unavailable)", data)
                else:
                    self.log_result(f"AI Consultation {i+1}", False, "Invalid response format", data)
                    all_passed = False
            else:
                self.log_result(f"AI Consultation {i+1}", False, f"HTTP {response.status_code}: {response.text}")
                all_passed = False
        
        return all_passed

    # ERROR HANDLING TESTS
    
    def test_error_handling(self):
        """Test error handling for malformed requests"""
        error_tests = [
            {
                "name": "Anomaly Training - Missing Samples",
                "endpoint": "/api/ml/anomaly/train",
                "data": {"algorithm": "isolation_forest"},
                "expected_status": 400
            },
            {
                "name": "Anomaly Prediction - Missing Telemetry",
                "endpoint": "/api/ml/anomaly/predict",
                "data": {},
                "expected_status": 400
            },
            {
                "name": "RL Training - Missing Policy Name",
                "endpoint": "/api/rl/policy/train",
                "data": {"episodes": 100},
                "expected_status": 400
            },
            {
                "name": "RL Action - Missing State",
                "endpoint": "/api/rl/policy/suggest-action",
                "data": {},
                "expected_status": 400
            },
            {
                "name": "AI Recommend - Missing Threat Data",
                "endpoint": "/api/ai/recommend",
                "data": {"analysis_style": "concise"},
                "expected_status": 400
            },
            {
                "name": "AI Consult - Missing Query",
                "endpoint": "/api/ai/consult",
                "data": {"context": {}},
                "expected_status": 400
            }
        ]
        
        all_passed = True
        
        for test in error_tests:
            response, success, error = self.make_request('POST', test["endpoint"], test["data"])
            
            if not success:
                self.log_result(test["name"], False, f"Request failed: {error}")
                all_passed = False
                continue
                
            if response.status_code == test["expected_status"]:
                self.log_result(test["name"], True, f"Correctly returned HTTP {response.status_code}")
            else:
                self.log_result(test["name"], False, f"Expected HTTP {test['expected_status']}, got {response.status_code}")
                all_passed = False
        
        return all_passed

    def run_all_tests(self):
        """Run comprehensive test suite"""
        print("🚀 Starting Comprehensive AI/ML Cybersecurity Suite Testing")
        print("=" * 70)
        
        # Initialize tracking variables
        self.isolation_forest_model_id = None
        self.svm_model_id = None
        self.policy_id = None
        
        test_phases = [
            ("PHASE 1: ANOMALY DETECTION", [
                ("Anomaly Status", self.test_anomaly_status),
                ("Anomaly Training", self.test_anomaly_training),
                ("Anomaly Prediction", self.test_anomaly_prediction)
            ]),
            ("PHASE 2: REINFORCEMENT LEARNING", [
                ("RL Status", self.test_rl_status),
                ("RL Training", self.test_rl_training),
                ("RL Action Suggestion", self.test_rl_action_suggestion)
            ]),
            ("PHASE 3: AI-POWERED ANALYSIS", [
                ("AI Threat Analysis", self.test_ai_threat_analysis),
                ("AI Remediation", self.test_ai_remediation),
                ("AI Consultation", self.test_ai_consultation)
            ]),
            ("ERROR HANDLING", [
                ("Error Handling", self.test_error_handling)
            ])
        ]
        
        total_tests = 0
        passed_tests = 0
        
        for phase_name, tests in test_phases:
            print(f"\n📋 {phase_name}")
            print("-" * 50)
            
            for test_name, test_func in tests:
                total_tests += 1
                try:
                    result = test_func()
                    if result:
                        passed_tests += 1
                except Exception as e:
                    self.log_result(test_name, False, f"Test exception: {str(e)}")
                    print(f"❌ FAIL {test_name}: Exception - {str(e)}")
        
        # Summary
        print("\n" + "=" * 70)
        print("📊 TEST SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Detailed results
        print(f"\n📝 DETAILED RESULTS:")
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"{status} {result['test']}: {result['details']}")
        
        return passed_tests, total_tests

def main():
    """Main test execution"""
    print("AI/ML Cybersecurity Suite - Backend API Testing")
    print("Testing against: http://localhost:3000")
    print("Timestamp:", datetime.now().isoformat())
    
    tester = CybersecurityAPITester()
    
    try:
        passed, total = tester.run_all_tests()
        
        # Exit with appropriate code
        if passed == total:
            print("\n🎉 All tests passed!")
            sys.exit(0)
        else:
            print(f"\n⚠️  {total - passed} tests failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Testing failed with exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()