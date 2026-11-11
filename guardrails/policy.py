"""Action Allow-List & Policy Enforcer.

Validates that LLM-suggested actions are in the authorized registry.
Any unauthorized action is silently sanitized to ``notify_analyst`` so
that the pipeline never executes an unexpected automated response.
"""

from typing import get_args

from llm.schemas import AllowedAction, TriageReport

# Derive the allow-list directly from the Literal type so the two
# definitions can never drift apart.
ALLOWED_ACTIONS: frozenset[str] = frozenset(get_args(AllowedAction))

# Fallback action used when an unauthorized action is detected.
SAFE_FALLBACK_ACTION: AllowedAction = "notify_analyst"


class PolicyEnforcer:
    """Enforces the action allow-list on triage reports.

    Attributes:
        allowed_actions: The set of permitted action strings.
    """

    def __init__(self) -> None:
        self.allowed_actions: frozenset[str] = ALLOWED_ACTIONS

    def validate_action(self, action: str) -> bool:
        """Return True if *action* is in the authorized registry."""
        return action in self.allowed_actions

    def sanitize_report(self, report: TriageReport) -> TriageReport:
        """Return a copy of *report* with any unauthorized action replaced.

        If ``report.suggested_action`` is not in the allow-list, the
        returned report's ``suggested_action`` is set to
        ``notify_analyst`` and a note is prepended to ``reasoning``.

        Args:
            report: The triage report to sanitize.

        Returns:
            A new :class:`~llm.schemas.TriageReport` instance (possibly
            with a sanitized action).
        """
        if self.validate_action(report.suggested_action):
            return report

        # Build sanitized copy without mutating the original.
        data = report.model_dump()
        original = data["suggested_action"]
        data["suggested_action"] = SAFE_FALLBACK_ACTION
        data["reasoning"] = (
            f"[POLICY] Action '{original}' is not in the allow-list and was "
            f"replaced with '{SAFE_FALLBACK_ACTION}'. "
            + data["reasoning"]
        )
        return TriageReport(**data)
