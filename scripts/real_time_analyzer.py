#!/usr/bin/env python3
"""
Real-time Threat Analysis Service
Continuously analyzes incoming network traffic for threats
"""

import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from threat_detection_engine import ThreatDetectionEngine
import pandas as pd

class RealTimeThreatAnalyzer:
    def __init__(self):
        self.engine = ThreatDetectionEngine()
        self.api_base = 'http://localhost:3000/api'
        self.last_processed_id = None
        self.analysis_interval = 5  # seconds
        
    async def start_analysis(self):
        """Start real-time threat analysis"""
        print("Starting real-time threat analysis...")
        
        # Load pre-trained models
        if not self.engine.load_models():
            print("No pre-trained models found. Training new models...")
            await self.train_initial_models()
        
        # Start analysis loop
        while True:
            try:
                await self.analyze_recent_traffic()
                await asyncio.sleep(self.analysis_interval)
            except KeyboardInterrupt:
                print("Stopping real-time analysis...")
                break
            except Exception as e:
                print(f"Error in analysis loop: {e}")
                await asyncio.sleep(self.analysis_interval)
    
    async def train_initial_models(self):
        """Train initial models if none exist"""
        async with aiohttp.ClientSession() as session:
            async with session.get(f'{self.api_base}/network-logs?limit=500') as response:
                if response.status == 200:
                    data = await response.json()
                    logs_df = pd.DataFrame(data['logs'])
                    
                    if len(logs_df) > 50:
                        print("Training initial models...")
                        self.engine.train_dos_detector(logs_df)
                        self.engine.train_port_scan_detector(logs_df)
                        self.engine.train_anomaly_detector(logs_df)
                        self.engine.save_models()
                        print("Initial model training completed")
                    else:
                        print("Insufficient data for model training")
    
    async def analyze_recent_traffic(self):
        """Analyze recent network traffic for threats"""
        async with aiohttp.ClientSession() as session:
            # Fetch recent network logs
            url = f'{self.api_base}/network-logs?limit=50'
            async with session.get(url) as response:
                if response.status != 200:
                    return
                
                data = await response.json()
                logs = data.get('logs', [])
                
                if not logs:
                    return
                
                # Process each log entry
                for log in logs:
                    if self.last_processed_id and log['id'] == self.last_processed_id:
                        break
                    
                    # Analyze for threats
                    threat_analysis = self.engine.predict_threat(log)
                    
                    # If high threat detected, create threat event
                    if threat_analysis.get('overall_threat_score', 0) > 0.7:
                        await self.create_threat_event(session, log, threat_analysis)
                    
                    # Update threat score in database
                    await self.update_threat_score(session, log['id'], threat_analysis)
                
                # Update last processed ID
                if logs:
                    self.last_processed_id = logs[0]['id']
    
    async def create_threat_event(self, session: aiohttp.ClientSession, 
                                log: dict, analysis: dict):
        """Create threat event based on analysis"""
        threat_type = 'unknown'
        description = 'AI-detected suspicious activity'
        
        # Determine threat type based on analysis
        if analysis.get('is_dos', False):
            threat_type = 'dos'
            description = 'DoS attack detected by ML model'
        elif analysis.get('is_anomaly', False):
            threat_type = 'malware'  # Assume anomalies are potential malware
            description = 'Anomalous network behavior detected'
        
        # Map threat level to severity
        severity_mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'minimal': 'low'
        }
        
        threat_event = {
            'threat_type': threat_type,
            'severity': severity_mapping.get(analysis.get('threat_level', 'medium'), 'medium'),
            'source_ip': log['source_ip'],
            'target_ip': log['destination_ip'],
            'port': log.get('destination_port'),
            'description': description,
            'status': 'active',
            'metadata': {
                'ai_detected': True,
                'threat_score': analysis.get('overall_threat_score', 0),
                'analysis_details': analysis,
                'source_log_id': log['id']
            }
        }
        
        try:
            async with session.post(f'{self.api_base}/threats', json=threat_event) as response:
                if response.status == 201:
                    result = await response.json()
                    print(f"Created AI-detected threat event: {result['threat']['id']}")
        except Exception as e:
            print(f"Error creating threat event: {e}")
    
    async def update_threat_score(self, session: aiohttp.ClientSession, 
                                log_id: str, analysis: dict):
        """Update network log with AI threat score"""
        update_data = {
            'threat_score': analysis.get('overall_threat_score', 0),
            'is_suspicious': analysis.get('overall_threat_score', 0) > 0.5,
            'metadata': {
                **json.loads(analysis.get('metadata', '{}')),
                'ai_analysis': analysis
            }
        }
        
        try:
            async with session.patch(f'{self.api_base}/network-logs/{log_id}', 
                                   json=update_data) as response:
                if response.status == 200:
                    print(f"Updated threat score for log {log_id}: {analysis.get('overall_threat_score', 0):.3f}")
        except Exception as e:
            print(f"Error updating threat score: {e}")

async def main():
    analyzer = RealTimeThreatAnalyzer()
    await analyzer.start_analysis()

if __name__ == "__main__":
    asyncio.run(main())
