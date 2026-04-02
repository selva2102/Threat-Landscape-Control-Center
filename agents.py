from typing import Any, Dict
from dataclasses import dataclass
from enum import Enum
import random

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Action(Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"  # Request MFA
    BLOCK = "block"
    REDIRECT_TO_DECEPTION = "redirect_to_deception"

@dataclass
class ThreatAssessment:
    """Result from an individual AI agent."""
    agent_name: str
    risk_score: float  # 0-1.0
    threat_level: ThreatLevel
    reasoning: str
    recommended_action: Action

@dataclass
class ConsensusDecision:
    """Final decision after multi-agent consensus."""
    average_risk_score: float
    final_threat_level: ThreatLevel
    final_action: Action
    agent_votes: list[ThreatAssessment]
    explanation: str  # Explainable AI output

class TriageAgent:
    """AI Triage Agent - probabilistic threat calculation."""
    
    def __init__(self, name: str):
        self.name = name
    
    def assess(self, indicator: Dict[str, Any]) -> ThreatAssessment:
        """Assess threat level with probabilistic risk scoring."""
        severity = indicator.get("severity", "low")
        ind_type = indicator.get("type", "unknown")
        
        # Base risk score by severity
        severity_risk = {
            "low": 0.2,
            "medium": 0.5,
            "high": 0.75,
            "critical": 0.95,
        }
        risk = severity_risk.get(severity, 0.3)
        
        # Type-based adjustments (with specialized perspective per agent)
        if self.name == "Network_Agent":
            if ind_type == "ip":
                risk += 0.15
        elif self.name == "Content_Agent":
            if ind_type == "domain":
                risk += 0.15
        elif self.name == "Malware_Agent":
            if ind_type == "hash":
                risk += 0.20
        
        # Cap at 1.0
        risk = min(risk, 1.0)
        
        # Add randomness to simulate independent analysis
        risk += random.uniform(-0.05, 0.05)
        risk = max(0.0, min(1.0, risk))
        
        # Map to threat level
        if risk >= 0.8:
            threat = ThreatLevel.CRITICAL
            action = Action.REDIRECT_TO_DECEPTION
        elif risk >= 0.6:
            threat = ThreatLevel.HIGH
            action = Action.BLOCK
        elif risk >= 0.4:
            threat = ThreatLevel.MEDIUM
            action = Action.CHALLENGE
        else:
            threat = ThreatLevel.LOW
            action = Action.ALLOW
        
        reasoning = f"{self.name} detected {ind_type}={indicator.get('value')} with risk={risk:.2f}"
        
        return ThreatAssessment(
            agent_name=self.name,
            risk_score=risk,
            threat_level=threat,
            reasoning=reasoning,
            recommended_action=action,
        )

class AutomatedDecisionEngine:
    """Autonomous Decision Engine - applies consensus and selects enforcement action."""
    
    def __init__(self):
        self.agents = [
            TriageAgent("Network_Agent"),
            TriageAgent("Content_Agent"),
            TriageAgent("Malware_Agent"),
        ]
    
    def reach_consensus(self, indicator: Dict[str, Any]) -> ConsensusDecision:
        """Multi-agent consensus for threat assessment."""
        agent_votes = []
        
        # Collect votes from all agents
        for agent in self.agents:
            assessment = agent.assess(indicator)
            agent_votes.append(assessment)
        
        # Calculate consensus metrics
        avg_risk = sum(v.risk_score for v in agent_votes) / len(agent_votes)
        
        # Determine final threat level based on average risk
        if avg_risk >= 0.8:
            final_threat = ThreatLevel.CRITICAL
            final_action = Action.REDIRECT_TO_DECEPTION
        elif avg_risk >= 0.6:
            final_threat = ThreatLevel.HIGH
            final_action = Action.BLOCK
        elif avg_risk >= 0.4:
            final_threat = ThreatLevel.MEDIUM
            final_action = Action.CHALLENGE
        else:
            final_threat = ThreatLevel.LOW
            final_action = Action.ALLOW
        
        # Generate Explainable AI (XAI) explanation
        xai_explanation = self._generate_xai_explanation(
            indicator, agent_votes, avg_risk, final_action
        )
        
        return ConsensusDecision(
            average_risk_score=avg_risk,
            final_threat_level=final_threat,
            final_action=final_action,
            agent_votes=agent_votes,
            explanation=xai_explanation,
        )
    
    def _generate_xai_explanation(
        self,
        indicator: Dict[str, Any],
        votes: list[ThreatAssessment],
        avg_risk: float,
        action: Action,
    ) -> str:
        """Generate human-readable explanation for the decision."""
        value = indicator.get("value", "unknown")
        ind_type = indicator.get("type", "unknown")
        
        explanation = f"Threat Analysis for {ind_type.upper()} '{value}':\n"
        explanation += f"  Consensus Risk Score: {avg_risk:.1%}\n"
        explanation += f"  Threat Level: {ThreatLevel(max([v.threat_level for v in votes], key=lambda x: x.value)).name}\n"
        explanation += f"  Recommended Action: {action.value.replace('_', ' ').upper()}\n\n"
        
        explanation += "Agent Assessments:\n"
        for vote in votes:
            explanation += f"  • {vote.agent_name}: {vote.reasoning} → {vote.recommended_action.value}\n"
        
        explanation += f"\nReasoning: "
        if action == Action.REDIRECT_TO_DECEPTION:
            explanation += "High confidence threat detected. Redirecting to Honey Pad for analysis and deception."
        elif action == Action.BLOCK:
            explanation += "Significant threat indicators. Blocking all traffic from this source."
        elif action == Action.CHALLENGE:
            explanation += "Moderate threat indicators. Requesting additional verification (MFA)."
        else:
            explanation += "Low threat indicators. Allowing traffic with monitoring."
        
        return explanation

# Global decision engine
decision_engine = AutomatedDecisionEngine()

MOCK_INDICATORS = [
    {"id": "ti-001", "type": "ip", "value": "192.168.1.1", "severity": "high", "source": "mock"},
    {"id": "ti-002", "type": "domain", "value": "malicious.com", "severity": "medium", "source": "mock"},
]

def create_report(indicators: list[Dict[str, Any]]) -> str:
    if not indicators:
        return "No indicators provided."
    summary = []
    counts = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    for i in indicators:
        sev = i.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
        summary.append(f"{i.get('type')} {i.get('value')} ({sev})")

    summary_text = "; ".join(summary)
    top = max(counts, key=counts.get)
    return f"Detected {len(indicators)} indicators. Severity distribution: {counts}. Top severity: {top}. Indicators: {summary_text}."


def threat_orchestrator():
    """Main orchestration function - executes the autonomous response workflow."""
    return {
        "indicators": MOCK_INDICATORS,
        "report": create_report(MOCK_INDICATORS)
    }

