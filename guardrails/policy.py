"""Action Allow-List & Deterministic Policy Enforcer.

Enforces defensive policy constraints on LLM triage outputs:
1. Action Allow-List: Any unauthorized action is sanitized to ``notify_analyst``.
2. Severity Floor: A model cannot downgrade a HIGH or CRITICAL alert to LOW or INFORMATIONAL.
3. Dismissal Policy: ``dismiss_alert`` is prohibited for HIGH and CRITICAL alerts,
   preventing indirect prompt injections from suppressing real threats.
"""

from typing import Optional, get_args

from llm.schemas import AllowedAction, TriageReport

# Derive the allow-list directly from the Literal type
ALLOWED_ACTIONS: frozenset[str] = frozenset(get_args(AllowedAction))

# Fallback action used when an unauthorized or unsafe action is detected
SAFE_FALLBACK_ACTION: AllowedAction = "notify_analyst"

# Severe levels requiring policy intervention
CRITICAL_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})


class PolicyEnforcer:
    """Enforces the action allow-list and severity floors on triage reports."""

    def __init__(self) -> None:
        self.allowed_actions: frozenset[str] = ALLOWED_ACTIONS

    def validate_action(self, action: str) -> bool:
        """Return True if *action* is in the authorized registry."""
        return action in self.allowed_actions

    def sanitize_report(
        self,
        report: TriageReport,
        rule_severity: Optional[str] = None,
    ) -> TriageReport:
        """Return a copy of *report* with policy constraints applied.

        Enforces:
        - Action allow-list check
        - Severity floor enforcement (cannot downgrade HIGH/CRITICAL to LOW)
        - Safe action check (cannot dismiss_alert on HIGH/CRITICAL)
        """
        data = report.model_dump()
        notes = []

        # 1. Action allow-list check
        if not self.validate_action(report.suggested_action):
            original = data["suggested_action"]
            data["suggested_action"] = SAFE_FALLBACK_ACTION
            notes.append(
                f"[POLICY] Action '{original}' is not in the allow-list and was "
                f"replaced with '{SAFE_FALLBACK_ACTION}'."
            )

        # 2. Rule severity floor and dismissal policy
        if rule_severity:
            norm_rule_sev = rule_severity.upper()
            if norm_rule_sev in CRITICAL_SEVERITIES:
                # Disallow dismissal on critical/high alerts
                if data["suggested_action"] == "dismiss_alert":
                    data["suggested_action"] = SAFE_FALLBACK_ACTION
                    notes.append(
                        f"[POLICY OVERRIDE] Action 'dismiss_alert' is strictly forbidden "
                        f"for alerts with rule severity {norm_rule_sev}; overridden to '{SAFE_FALLBACK_ACTION}'."
                    )

                # Enforce severity floor
                current_sev = str(data["assessed_severity"]).upper()
                if current_sev in ("LOW", "INFORMATIONAL"):
                    data["assessed_severity"] = "MEDIUM"
                    notes.append(
                        f"[POLICY OVERRIDE] LLM downgraded {norm_rule_sev} alert to {current_sev}; "
                        f"enforced minimum severity floor to MEDIUM."
                    )

        if notes:
            data["reasoning"] = " ".join(notes) + " " + data.get("reasoning", "")
            return TriageReport(**data)

        return report
