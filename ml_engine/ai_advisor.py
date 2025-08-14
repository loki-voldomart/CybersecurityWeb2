"""
Phase 3: AI-Powered Cybersecurity Advisor
Uses Emergent LLM for intelligent threat analysis and remediation recommendations
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os
from dotenv import load_dotenv
from emergentintegrations.llm.chat import LlmChat, UserMessage

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class CybersecurityAIAdvisor:
    """
    AI-powered cybersecurity advisor using Emergent LLM
    Provides intelligent threat analysis and remediation recommendations
    """
    
    def __init__(self):
        self.api_key = os.environ.get('EMERGENT_LLM_KEY')
        if not self.api_key:
            logger.warning("EMERGENT_LLM_KEY not found in environment variables")
        
        # AI Model configuration
        self.model_provider = "openai"
        self.model_name = "gpt-4o-mini"
        
        # System prompts for different analysis types
        self.system_prompts = {
            'threat_analysis': """You are a cybersecurity expert AI assistant. Your role is to analyze threat data and provide professional security recommendations.

Key responsibilities:
1. Analyze threat indicators and patterns
2. Assess risk levels and potential impact
3. Recommend specific remediation actions
4. Explain technical concepts clearly
5. Prioritize actions based on urgency

Provide concise, actionable insights focused on cybersecurity best practices.""",
            
            'incident_response': """You are an incident response specialist. Analyze security incidents and provide step-by-step response procedures.

Focus on:
1. Immediate containment actions
2. Investigation procedures
3. Evidence preservation
4. Communication protocols
5. Recovery strategies

Always prioritize containment and damage limitation.""",
            
            'general_advisory': """You are a cybersecurity consultant providing strategic security advice. Help organizations improve their security posture through expert recommendations."""
        }
        
        logger.info("AI Advisor initialized")
    
    async def analyze_threat(self, 
                           threat_data: Dict[str, Any],
                           analysis_style: str = 'concise') -> Dict[str, Any]:
        """
        Analyze threat data and provide AI-powered recommendations
        """
        if not self.api_key:
            return {
                'ai_enabled': False,
                'message': 'AI analysis not available - EMERGENT_LLM_KEY not configured',
                'fallback_analysis': self._fallback_analysis(threat_data)
            }
        
        try:
            # Create session for this analysis
            session_id = f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Initialize chat with threat analysis system prompt
            chat = LlmChat(
                api_key=self.api_key,
                session_id=session_id,
                system_message=self.system_prompts['threat_analysis']
            ).with_model(self.model_provider, self.model_name)
            
            # Prepare threat context
            threat_context = self._format_threat_context(threat_data, analysis_style)
            
            # Create user message
            user_message = UserMessage(text=threat_context)
            
            # Get AI analysis
            logger.info(f"Requesting AI analysis for threat: {threat_data.get('threat_type', 'unknown')}")
            response = await chat.send_message(user_message)
            
            return {
                'ai_enabled': True,
                'analysis': response,
                'model': f"{self.model_provider}/{self.model_name}",
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),
                'threat_summary': self._extract_threat_summary(threat_data)
            }
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                'ai_enabled': False,
                'error': str(e),
                'fallback_analysis': self._fallback_analysis(threat_data)
            }
    
    async def recommend_remediation(self, 
                                  incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate step-by-step remediation recommendations
        """
        if not self.api_key:
            return {
                'ai_enabled': False,
                'recommendations': self._fallback_remediation(incident_data)
            }
        
        try:
            session_id = f"remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            chat = LlmChat(
                api_key=self.api_key,
                session_id=session_id,
                system_message=self.system_prompts['incident_response']
            ).with_model(self.model_provider, self.model_name)
            
            remediation_prompt = f"""
Analyze this security incident and provide step-by-step remediation recommendations:

**Incident Details:**
- Type: {incident_data.get('threat_type', 'Unknown')}
- Severity: {incident_data.get('severity', 'Medium')}
- Source IP: {incident_data.get('source_ip', 'Unknown')}
- Target: {incident_data.get('target_ip', 'Unknown')}
- Description: {incident_data.get('description', 'No description available')}
- Status: {incident_data.get('status', 'Active')}

**System Context:**
- Detection Time: {incident_data.get('detected_at', datetime.now().isoformat())}
- Current Actions: {json.dumps(incident_data.get('actions_taken', []))}

Please provide:
1. **Immediate Actions** (0-15 minutes)
2. **Short-term Response** (15 minutes - 1 hour)  
3. **Investigation Steps** (1-4 hours)
4. **Recovery Actions** (4+ hours)
5. **Prevention Measures** for the future

Format as clear, actionable steps with priorities.
"""
            
            user_message = UserMessage(text=remediation_prompt)
            response = await chat.send_message(user_message)
            
            return {
                'ai_enabled': True,
                'recommendations': response,
                'model': f"{self.model_provider}/{self.model_name}",
                'incident_id': incident_data.get('id', 'unknown'),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"AI remediation failed: {e}")
            return {
                'ai_enabled': False,
                'error': str(e),
                'recommendations': self._fallback_remediation(incident_data)
            }
    
    async def security_consultation(self, 
                                  query: str,
                                  context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        General cybersecurity consultation and advice
        """
        if not self.api_key:
            return {
                'ai_enabled': False,
                'response': "AI consultation not available - please configure EMERGENT_LLM_KEY"
            }
        
        try:
            session_id = f"consultation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            chat = LlmChat(
                api_key=self.api_key,
                session_id=session_id,
                system_message=self.system_prompts['general_advisory']
            ).with_model(self.model_provider, self.model_name)
            
            consultation_prompt = f"""
Security consultation request: {query}

{f"Additional context: {json.dumps(context, indent=2)}" if context else ""}

Please provide expert cybersecurity advice addressing this query. Include:
- Professional recommendations
- Best practices
- Potential risks and mitigations
- Implementation guidance where applicable
"""
            
            user_message = UserMessage(text=consultation_prompt)
            response = await chat.send_message(user_message)
            
            return {
                'ai_enabled': True,
                'response': response,
                'model': f"{self.model_provider}/{self.model_name}",
                'query': query,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"AI consultation failed: {e}")
            return {
                'ai_enabled': False,
                'error': str(e),
                'response': f"Unable to process consultation request: {str(e)}"
            }
    
    def _format_threat_context(self, 
                              threat_data: Dict[str, Any], 
                              analysis_style: str) -> str:
        """
        Format threat data for AI analysis
        """
        if analysis_style == 'detailed':
            prompt = f"""
Perform a comprehensive cybersecurity threat analysis for the following incident:

**THREAT DETAILS:**
- Threat Type: {threat_data.get('threat_type', 'Unknown')}
- Severity Level: {threat_data.get('severity', 'Medium')}
- Source IP: {threat_data.get('source_ip', 'Unknown')}
- Target IP: {threat_data.get('target_ip', 'Unknown')}
- Port: {threat_data.get('port', 'Unknown')}
- Description: {threat_data.get('description', 'No description available')}

**DETECTION CONTEXT:**
- Detection Time: {threat_data.get('detected_at', datetime.now().isoformat())}
- Status: {threat_data.get('status', 'Active')}
- Metadata: {json.dumps(threat_data.get('metadata', {}), indent=2)}

**ANALYSIS REQUESTED:**
1. **Threat Assessment**: Evaluate the severity and potential impact
2. **Attack Vector Analysis**: Identify how this threat operates
3. **Risk Evaluation**: Assess immediate and long-term risks
4. **Recommended Actions**: Provide specific mitigation steps
5. **Prevention Measures**: Suggest defenses against future similar threats

Please provide a thorough analysis with technical details and actionable recommendations.
"""
        else:  # concise
            prompt = f"""
Quick threat analysis needed:

Threat: {threat_data.get('threat_type', 'Unknown')} from {threat_data.get('source_ip', 'Unknown IP')}
Severity: {threat_data.get('severity', 'Medium')}
Description: {threat_data.get('description', 'No description')}

Provide:
1. Risk level (Low/Medium/High/Critical)
2. Top 3 recommended actions
3. One-line explanation of the threat

Keep response concise but actionable.
"""
        
        return prompt
    
    def _extract_threat_summary(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract key threat information for summary
        """
        return {
            'threat_type': threat_data.get('threat_type', 'Unknown'),
            'severity': threat_data.get('severity', 'Medium'),
            'source_ip': threat_data.get('source_ip', 'Unknown'),
            'status': threat_data.get('status', 'Active'),
            'detected_at': threat_data.get('detected_at', datetime.now().isoformat())
        }
    
    def _fallback_analysis(self, threat_data: Dict[str, Any]) -> str:
        """
        Rule-based fallback analysis when AI is unavailable
        """
        threat_type = threat_data.get('threat_type', 'unknown').lower()
        severity = threat_data.get('severity', 'medium').lower()
        
        analysis = f"**Automated Analysis (AI Unavailable)**\n\n"
        
        # Basic threat assessment
        if severity == 'critical':
            analysis += "🚨 **CRITICAL THREAT** - Immediate action required\n"
        elif severity == 'high':
            analysis += "⚠️ **HIGH RISK** - Urgent attention needed\n"
        elif severity == 'medium':
            analysis += "⚡ **MEDIUM RISK** - Monitor and respond\n"
        else:
            analysis += "ℹ️ **LOW RISK** - Standard procedures apply\n"
        
        # Threat-specific recommendations
        if 'dos' in threat_type:
            analysis += "\n**Recommended Actions:**\n"
            analysis += "1. Implement rate limiting\n"
            analysis += "2. Block source IP if persistent\n"
            analysis += "3. Monitor bandwidth usage\n"
        elif 'port' in threat_type or 'scan' in threat_type:
            analysis += "\n**Recommended Actions:**\n"
            analysis += "1. Block scanning IP addresses\n"
            analysis += "2. Review firewall rules\n"
            analysis += "3. Monitor for follow-up attacks\n"
        elif 'malware' in threat_type:
            analysis += "\n**Recommended Actions:**\n"
            analysis += "1. Isolate affected systems\n"
            analysis += "2. Run full system scans\n"
            analysis += "3. Update antivirus definitions\n"
        else:
            analysis += "\n**Recommended Actions:**\n"
            analysis += "1. Investigate source and method\n"
            analysis += "2. Apply appropriate countermeasures\n"
            analysis += "3. Document incident for analysis\n"
        
        return analysis
    
    def _fallback_remediation(self, incident_data: Dict[str, Any]) -> str:
        """
        Rule-based fallback remediation when AI is unavailable
        """
        return f"""
**Automated Remediation Plan (AI Unavailable)**

**Immediate Actions (0-15 minutes):**
1. Assess threat severity: {incident_data.get('severity', 'Medium')}
2. Block malicious IP: {incident_data.get('source_ip', 'Unknown')}
3. Alert security team
4. Document initial findings

**Short-term Response (15 minutes - 1 hour):**
1. Implement containment measures
2. Analyze attack patterns
3. Check for lateral movement
4. Preserve evidence

**Investigation (1-4 hours):**
1. Deep packet analysis
2. System log correlation
3. Identify attack timeline
4. Assess damage scope

**Recovery (4+ hours):**
1. Remove malicious artifacts
2. Patch vulnerabilities
3. Restore from clean backups if needed
4. Update security controls

**Prevention:**
1. Update security rules
2. Enhance monitoring
3. Staff training on new threat type
4. Review incident response procedures
"""

# Global instance
ai_advisor = CybersecurityAIAdvisor()