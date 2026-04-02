from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from agents import threat_orchestrator, decision_engine, Action, ThreatLevel
import os
import re
from datetime import datetime
import socket

class ChatRequest(BaseModel):
    message: str
    history: list = None

class IndicatorRequest(BaseModel):
    indicator: dict

app = FastAPI(title="Autonomous AI-Powered Adaptive Cyber Threat Response Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MOCK_INDICATORS = [
    {
        "id": "ti-001",
        "type": "domain",
        "value": "example.com",
        "severity": "low",
        "source": "mock",
        "firstSeen": "2026-03-01",
        "lastSeen": "2026-03-10",
    },
    {
        "id": "ti-002",
        "type": "ip",
        "value": "203.0.113.45",
        "severity": "medium",
        "source": "mock",
        "firstSeen": "2026-03-02",
        "lastSeen": "2026-03-11",
    },
    {
        "id": "ti-003",
        "type": "hash",
        "value": "44d88612fea8a8f36de82e1278abb02f",
        "severity": "high",
        "source": "mock",
        "firstSeen": "2026-03-03",
        "lastSeen": "2026-03-12",
    },
]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/indicators")
def indicators(q: str = Query(default="")) -> dict:
    q_str = str(q) if q else ""
    if not q_str:
        return {"items": MOCK_INDICATORS}
    q_lower = q_str.lower()
    filtered = [i for i in MOCK_INDICATORS if q_lower in i["value"].lower()]
    # Return empty filtered results so frontend can show no matches, not fallback to full set.
    return {"items": filtered}

class PhishingDetector:
    """Detect phishing indicators: IPs, domains, and hashes from text."""
    
    @staticmethod
    def detect_ips(text: str) -> list:
        """Extract IP addresses from text."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        return [
            {
                "id": f"ph-ip-{i}",
                "type": "ip",
                "value": ip,
                "severity": "high",
                "source": "phishing_detector",
                "firstSeen": datetime.now().isoformat(),
                "lastSeen": datetime.now().isoformat(),
            }
            for i, ip in enumerate(set(ips))
        ]
    
    @staticmethod
    def detect_domains(text: str) -> list:
        """Extract domains from text."""
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text.lower())
        return [
            {
                "id": f"ph-domain-{i}",
                "type": "domain",
                "value": domain,
                "severity": "medium",
                "source": "phishing_detector",
                "firstSeen": datetime.now().isoformat(),
                "lastSeen": datetime.now().isoformat(),
            }
            for i, domain in enumerate(set(domains))
        ]
    
    @staticmethod
    def detect_hashes(text: str) -> list:
        """Extract MD5, SHA1, SHA256 hashes from text."""
        hashes = []
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        md5s = re.findall(md5_pattern, text)
        for h in set(md5s):
            hashes.append({
                "id": f"ph-hash-md5-{len(hashes)}",
                "type": "hash",
                "value": h,
                "severity": "critical",
                "source": "phishing_detector",
                "hashType": "MD5",
                "firstSeen": datetime.now().isoformat(),
                "lastSeen": datetime.now().isoformat(),
            })
        
        sha1s = re.findall(sha1_pattern, text)
        for h in set(sha1s):
            hashes.append({
                "id": f"ph-hash-sha1-{len(hashes)}",
                "type": "hash",
                "value": h,
                "severity": "critical",
                "source": "phishing_detector",
                "hashType": "SHA1",
                "firstSeen": datetime.now().isoformat(),
                "lastSeen": datetime.now().isoformat(),
            })
        
        sha256s = re.findall(sha256_pattern, text)
        for h in set(sha256s):
            hashes.append({
                "id": f"ph-hash-sha256-{len(hashes)}",
                "type": "hash",
                "value": h,
                "severity": "critical",
                "source": "phishing_detector",
                "hashType": "SHA256",
                "firstSeen": datetime.now().isoformat(),
                "lastSeen": datetime.now().isoformat(),
            })
        
        return hashes
    
    @staticmethod
    def detect_all(text: str) -> dict:
        """Detect all phishing indicators in text."""
        ips = PhishingDetector.detect_ips(text)
        domains = PhishingDetector.detect_domains(text)
        hashes = PhishingDetector.detect_hashes(text)
        
        all_indicators = ips + domains + hashes
        return {
            "ips": ips,
            "domains": domains,
            "hashes": hashes,
            "all": all_indicators,
            "total": len(all_indicators),
        }

@app.post("/detect-phishing")
def detect_phishing(request: ChatRequest):
    """Detect phishing indicators (IPs, domains, hashes) from text input."""
    text = request.message.strip()
    if not text:
        return {"status": "error", "message": "No text provided", "results": None}
    
    results = PhishingDetector.detect_all(text)
    return {
        "status": "success",
        "message": f"Found {results['total']} phishing indicators",
        "results": results,
    }

@app.post("/simulate-attack")
def simulate_attack():
    """Simulate a cyber attack and return the result."""
    try:
        # Prefer direct socket connection so it works inside Docker too.
        honeypot_host = os.getenv("HONEYPOT_HOST", "honeypot")
        honeypot_port = int(os.getenv("HONEYPOT_PORT", "22"))

        payload = b"Simulated malicious payload\n"
        with socket.create_connection((honeypot_host, honeypot_port), timeout=5) as sock:
            sock.sendall(payload)

        return {
            "status": "success",
            "message": "Attack simulation completed successfully",
            "output": f"Sent payload to {honeypot_host}:{honeypot_port}",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Failed to run attack simulation",
            "error": str(e)
        }

@app.post("/threat-assessment")
def threat_assessment(request: IndicatorRequest):
    """
    THE BRAIN: Multi-agent consensus threat assessment with Explainable AI (XAI).
    Uses the Autonomous Decision Engine for probabilistic risk scoring.
    """
    indicator = request.indicator
    
    try:
        consensus = decision_engine.reach_consensus(indicator)
        
        return {
            "status": "success",
            "indicator": indicator,
            "risk_score": consensus.average_risk_score,
            "threat_level": consensus.final_threat_level.value,
            "action": consensus.final_action.value,
            "explanation": consensus.explanation,
            "agent_votes": [
                {
                    "agent": v.agent_name,
                    "risk_score": v.risk_score,
                    "threat_level": v.threat_level.value,
                    "reasoning": v.reasoning,
                }
                for v in consensus.agent_votes
            ],
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Threat assessment failed",
            "error": str(e),
        }

@app.post("/autonomous-action")
def autonomous_action(request: IndicatorRequest):
    """
    THE MUSCLE: Execute the automated response decision.
    Applies enforcement actions: ALLOW, CHALLENGE, BLOCK, or REDIRECT_TO_DECEPTION.
    """
    indicator = request.indicator
    
    try:
        consensus = decision_engine.reach_consensus(indicator)
        action = consensus.final_action
        
        # Simulate action execution
        execution_log = {
            "timestamp": datetime.now().isoformat(),
            "indicator": indicator,
            "action": action.value,
            "status": "executed",
        }
        
        if action == Action.ALLOW:
            execution_log["description"] = "Traffic allowed with monitoring enabled."
        elif action == Action.CHALLENGE:
            execution_log["description"] = "Challenge issued: MFA verification requested."
        elif action == Action.BLOCK:
            execution_log["description"] = "Traffic blocked. Connection terminated."
        elif action == Action.REDIRECT_TO_DECEPTION:
            execution_log["description"] = f"Attacker redirected to Honey Pad (Deception Environment) for isolation and analysis."
            # In production, this would spawn a containerized honeypot
            execution_log["honey_pad_id"] = f"honey-pad-{indicator.get('id', 'unknown')}"
        
        return {
            "status": "success",
            "execution": execution_log,
            "xai_explanation": consensus.explanation,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Autonomous action execution failed",
            "error": str(e),
        }

@app.post("/analyze")
def analyze():
    """
    Orchestrated threat analysis endpoint.
    Returns all indicators and a threat analysis report.
    """
    try:
        # Get all indicators directly
        all_indicators = MOCK_INDICATORS
        
        # Analyze each indicator
        threat_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        
        total_risk_score = 0.0
        for indicator in all_indicators:
            severity = indicator.get("severity", "low")
            threat_summary[severity] = threat_summary.get(severity, 0) + 1
            total_risk_score += (1.0 / len(all_indicators)) if all_indicators else 0
        
        # Generate threat report
        critical_count = threat_summary.get("critical", 0)
        high_count = threat_summary.get("high", 0)
        medium_count = threat_summary.get("medium", 0)
        total_threats = len(all_indicators)
        
        report = f"""
THREAT ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total Indicators: {total_threats}
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {threat_summary.get('low', 0)}

Average Risk Score: {(total_risk_score * 100):.1f}%

ANALYSIS SUMMARY:
"""
        
        if critical_count > 0:
            report += f"⚠️ CRITICAL THREATS DETECTED: {critical_count} critical indicators found. Immediate action required.\n"
        
        if high_count > 0:
            report += f"🔴 HIGH SEVERITY: {high_count} high-severity threats detected.\n"
        
        if medium_count > 0:
            report += f"🟡 MEDIUM SEVERITY: {medium_count} medium-severity threats detected.\n"
        
        if total_threats == 0:
            report += "✅ No threats detected. System is secure.\n"
        
        report += "\nRECOMMENDATION: "
        if critical_count > 0:
            report += "Block all critical indicators. Execute deception techniques to isolate attackers."
        elif high_count > 0:
            report += "Challenge high-severity traffic. Enable enhanced monitoring."
        elif total_threats > 0:
            report += "Continue monitoring. Escalate if threats increase."
        else:
            report += "Maintain current security posture."
        
        return {
            "status": "success",
            "report": report,
            "indicators": all_indicators,
            "threat_summary": threat_summary,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Analysis failed",
            "error": str(e),
        }
