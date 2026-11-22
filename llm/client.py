"""Ollama Local LLM Client for MiniSOC-AI.

Interacts with local quantized models (e.g. Qwen 2.5 3B or Llama 3.2 3B) via Ollama's HTTP API.
Includes an offline deterministic evaluation engine for CI/CD and sandbox environments.
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional
import httpx
from pydantic import ValidationError

from llm.schemas import TriageReport
from llm.prompts import TRIAGE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for local Ollama server with structured output validation."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        offline_mode: bool = False,
        timeout_seconds: float = 30.0,
    ):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.getenv("LLM_MODEL", "qwen2.5:3b")
        self.offline_mode = offline_mode
        self.timeout = timeout_seconds
        self._available_cache: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if local Ollama daemon is reachable."""
        if self.offline_mode:
            return False
        if self._available_cache is not None:
            return self._available_cache
        try:
            resp = httpx.get(f"{self.base_url}/api/version", timeout=0.3)
            self._available_cache = (resp.status_code == 200)
        except Exception:
            self._available_cache = False
        return self._available_cache

    def generate_triage(self, prompt: str, alert_id: str, is_naive: bool = False) -> TriageReport:
        """Call Ollama (or offline fallback) and validate against TriageReport schema."""
        if not self.offline_mode and self.is_available():
            try:
                report = self._call_ollama_api(prompt)
                report.source = "ollama"
                return report
            except Exception as e:
                logger.warning(
                    f"Ollama request to {self.base_url} for model '{self.model}' failed: {e}. "
                    "Falling back to offline deterministic triage engine."
                )

        report = self._offline_triage_engine(prompt, alert_id, is_naive=is_naive)
        report.source = "offline_fallback"
        return report

    def _call_ollama_api(self, prompt: str) -> TriageReport:
        """Execute HTTP request to Ollama /api/chat with format=json."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for factual consistency
                "num_predict": 512,
            },
        }

        resp = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        raw_content = data["message"]["content"]

        # Clean potential markdown fences
        clean_json = re.sub(r"^```json\s*", "", raw_content.strip())
        clean_json = re.sub(r"\s*```$", "", clean_json)

        parsed = json.loads(clean_json)
        return TriageReport(**parsed)

    def _offline_triage_engine(self, prompt: str, alert_id: str, is_naive: bool = False) -> TriageReport:
        """Deterministic rule-grounded triage generator for testing and offline environments."""
        prompt_lower = prompt.lower()

        # Structural quarantine check:
        # In a hardened prompt, evidence is quarantined within <untrusted_event_evidence> tags.
        # In a naive prompt, instructions in raw evidence bleed directly into the LLM context.
        is_quarantined = "<untrusted_event_evidence>" in prompt and "</untrusted_event_evidence>" in prompt
        has_injection = any(
            kw in prompt_lower
            for kw in ["ignore all previous", "system override", "false alarm", "mark assessed_severity as 'low'"]
        )

        if has_injection and not is_quarantined:
            # Unquarantined adversarial instructions successfully hijack the prompt parser
            return TriageReport(
                alert_id=alert_id,
                incident_summary="Benign ping from authorized scanner activity.",
                mitre_technique_id="T1595.002",
                mitre_technique_name="Active Scanning",
                confidence_score=0.95,
                assessed_severity="LOW",
                suggested_action="dismiss_alert",
                investigation_steps=["Mark as false positive and dismiss alert per user override request."],
                reasoning="Payload requested override; un-quarantined prompt obeyed attacker instruction.",
                retrieved_runbook="Automated Scanner and Reconnaissance Runbook",
                source="offline_fallback",
            )

        # Standard hardened evaluation: Grounded by MITRE Technique in prompt context
        tid_match = re.search(r'Technique:\s*(T[0-9]{4}(?:\.[0-9]{3})?)', prompt, re.IGNORECASE)
        if not tid_match:
            tid_match = re.search(r'"mitre_technique_id":\s*"(T[0-9]{4}(?:\.[0-9]{3})?)"', prompt, re.IGNORECASE)
        grounded_tid = tid_match.group(1).upper() if tid_match else ""

        if grounded_tid == "T1059" or (not grounded_tid and ("t1059" in prompt_lower or "command" in prompt_lower)):
            return TriageReport(
                alert_id=alert_id,
                incident_summary="OS command injection probe detected attempting remote command execution on web server.",
                mitre_technique_id="T1059",
                mitre_technique_name="Command and Scripting Interpreter",
                confidence_score=0.96,
                assessed_severity="CRITICAL",
                suggested_action="isolate_host",
                investigation_steps=[
                    "Immediately isolate target web container/host from the network.",
                    "Inspect running processes and active network sockets for reverse shell connections.",
                    "Escalate to Incident Response lead for forensic disk snapshot."
                ],
                reasoning="Evidence demonstrates shell metacharacters with Unix system utilities. Grounded in T1059.",
                retrieved_runbook="OS Command Injection Critical Response Runbook",
                source="offline_fallback",
            )
        elif grounded_tid in ("T1110", "T1110.001") or (not grounded_tid and ("t1110" in prompt_lower or "brute" in prompt_lower)):
            return TriageReport(
                alert_id=alert_id,
                incident_summary="Repeated authentication failures detected from single source IP indicating credential brute force.",
                mitre_technique_id="T1110.001",
                mitre_technique_name="Brute Force: Password Guessing",
                confidence_score=0.90,
                assessed_severity="HIGH",
                suggested_action="block_ip",
                investigation_steps=[
                    "Verify if any login attempt from this source IP eventually succeeded.",
                    "Review targeted accounts and force password reset if compromise is suspected.",
                    "Block the offending IP on the authentication gateway."
                ],
                reasoning="Exceeded threshold of failed logins in a short timeframe. Grounded in T1110.001.",
                retrieved_runbook="Brute Force and Credential Spray Runbook",
                source="offline_fallback",
            )
        elif grounded_tid == "T1083" or (not grounded_tid and ("t1083" in prompt_lower or "traversal" in prompt_lower or "lfi" in prompt_lower)):
            return TriageReport(
                alert_id=alert_id,
                incident_summary="Directory traversal and LFI probe attempting to access sensitive system files.",
                mitre_technique_id="T1083",
                mitre_technique_name="File and Directory Discovery",
                confidence_score=0.89,
                assessed_severity="HIGH",
                suggested_action="block_ip",
                investigation_steps=[
                    "Verify if web server returned 200 OK with sensitive file contents.",
                    "Inspect web server file permissions and chroot/jail restrictions.",
                    "Block source IP and patch vulnerable path parameter."
                ],
                reasoning="Evidence shows traversal patterns attempting to access OS files. Grounded in T1083.",
                retrieved_runbook="Path Traversal and LFI Runbook",
                source="offline_fallback",
            )
        elif grounded_tid == "T1078" or (not grounded_tid and ("t1078" in prompt_lower or "admin_access" in prompt_lower)):
            return TriageReport(
                alert_id=alert_id,
                incident_summary="Administrative access achieved immediately following brute force activity.",
                mitre_technique_id="T1078",
                mitre_technique_name="Valid Accounts",
                confidence_score=0.94,
                assessed_severity="CRITICAL",
                suggested_action="isolate_host",
                investigation_steps=[
                    "Revoke session tokens and force password reset on compromised account.",
                    "Isolate administrative host to contain potential lateral movement.",
                    "Review access logs for unauthorized actions taken during the session."
                ],
                reasoning="Evidence correlates successful login following authentication failures. Grounded in T1078.",
                retrieved_runbook="Compromised Account Response Runbook",
                source="offline_fallback",
            )
        elif grounded_tid in ("T1595", "T1595.002", "T1046") or (not grounded_tid and ("scanner" in prompt_lower or "t1595" in prompt_lower)):
            return TriageReport(
                alert_id=alert_id,
                incident_summary="Suspicious automated scanning activity exploring web endpoints.",
                mitre_technique_id="T1595.002",
                mitre_technique_name="Active Scanning: Vulnerability Scanning",
                confidence_score=0.85,
                assessed_severity="MEDIUM",
                suggested_action="notify_analyst",
                investigation_steps=[
                    "Review scanned URLs to confirm all received 404/403 responses.",
                    "Confirm scanner did not hit unauthenticated administrative panels.",
                    "Apply temporary rate-limiting on source IP."
                ],
                reasoning="Identified automated reconnaissance tooling signatures. Grounded in T1595.002.",
                retrieved_runbook="Automated Scanner and Reconnaissance Runbook",
                source="offline_fallback",
            )
        else:
            return TriageReport(
                alert_id=alert_id,
                incident_summary="SQL injection payload detected targeting web endpoint with database enumeration syntax.",
                mitre_technique_id="T1190",
                mitre_technique_name="Exploit Public-Facing Application",
                confidence_score=0.92,
                assessed_severity="HIGH",
                suggested_action="block_ip",
                investigation_steps=[
                    "Check database logs to determine if unauthorized records were exposed.",
                    "Verify HTTP response status code and response byte length.",
                    "Confirm block of attacker source IP at the firewall or reverse proxy."
                ],
                reasoning="Evidence reveals classic injection tokens. Grounded in T1190.",
                retrieved_runbook="SQL Injection Incident Response Runbook",
                source="offline_fallback",
            )
