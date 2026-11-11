"""MiniSOC-AI Streamlit Dashboard.

Launch with:
    streamlit run dashboard/app.py

The app reads from the DuckDB database and audit log in real-time.
No Ollama / LLM daemon is required; the page shows what has already
been triaged and recorded.

Pages / Sections:
  1. Overview      -- KPI tiles + alert volume chart
  2. Alerts        -- Recent alerts table with severity badges
  3. MITRE Heatmap -- Technique coverage bar chart
  4. Approvals     -- Pending queue + decision history
  5. Audit Chain   -- Tamper verification widget
  6. Feedback      -- Analyst FP/TP feedback form + summary
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running from repo root: `streamlit run dashboard/app.py`
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import streamlit as st

from dashboard.data import (
    alert_severity_counts,
    alert_volume_by_hour,
    approval_history,
    audit_chain_status,
    feedback_summary,
    mitre_coverage,
    pending_approvals,
    recent_alerts,
    store_feedback,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="MiniSOC-AI Dashboard",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = os.getenv("MINISOC_DB", "data/minisoc.duckdb")
AUDIT_LOG = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl")

# ---------------------------------------------------------------------------
# Sidebar — navigation
# ---------------------------------------------------------------------------

st.sidebar.title("MiniSOC-AI")
st.sidebar.caption("On-premise AI-assisted SOC")

page = st.sidebar.radio(
    "Navigate",
    [
        "Overview",
        "Alerts",
        "MITRE Coverage",
        "Approvals",
        "Audit Chain",
        "Analyst Feedback",
    ],
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**DB:** `" + DB_PATH + "`  \n"
    "**Audit log:** `" + AUDIT_LOG + "`"
)

if st.sidebar.button("Refresh data"):
    st.cache_data.clear()

# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#27ae60",
}


def _severity_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev.upper(), "#7f8c8d")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em">{sev}</span>'


# ===========================================================================
# PAGE: Overview
# ===========================================================================

if page == "Overview":
    st.title("MiniSOC-AI — Overview")

    sev_df = alert_severity_counts(DB_PATH)
    vol_df = alert_volume_by_hour(DB_PATH)
    pend_df = pending_approvals(DB_PATH)
    chain = audit_chain_status(AUDIT_LOG)

    # KPI tiles
    col1, col2, col3, col4 = st.columns(4)
    total_alerts = int(sev_df["count"].sum()) if not sev_df.empty else 0
    critical = int(
        sev_df.loc[sev_df["severity"] == "CRITICAL", "count"].sum()
    ) if not sev_df.empty else 0
    pending_count = len(pend_df)
    chain_ok = chain["valid"]

    col1.metric("Total Alerts", total_alerts)
    col2.metric("CRITICAL Alerts", critical, delta=None)
    col3.metric("Pending Approvals", pending_count)
    col4.metric(
        "Audit Chain",
        "VALID" if chain_ok else "TAMPERED",
        delta=None,
        delta_color="off",
    )
    if not chain_ok:
        st.error(
            f"Audit chain integrity FAILED at entry index {chain['broken_at']}!"
        )

    st.markdown("---")

    # Alert volume over time
    st.subheader("Alert Volume by Hour")
    if vol_df.empty:
        st.info("No alert data yet. Run the detection engine to populate.")
    else:
        st.bar_chart(vol_df.set_index("hour")["count"])

    # Severity breakdown
    st.subheader("Alerts by Severity")
    if sev_df.empty:
        st.info("No severity data.")
    else:
        st.bar_chart(sev_df.set_index("severity")["count"])


# ===========================================================================
# PAGE: Alerts
# ===========================================================================

elif page == "Alerts":
    st.title("Recent Alerts")

    df = recent_alerts(DB_PATH, limit=100)
    if df.empty:
        st.info("No alerts found. Run `py detections/cli.py` to scan events.")
    else:
        # Severity filter
        sevs = ["ALL"] + sorted(df["severity"].unique().tolist())
        sel = st.selectbox("Filter by severity", sevs)
        if sel != "ALL":
            df = df[df["severity"] == sel]

        st.write(f"Showing {len(df)} alerts")

        # Render with coloured severity column
        for _, row in df.iterrows():
            badge = _severity_badge(str(row.get("severity", "")))
            with st.expander(
                f"[{row.get('rule_id', '')}]  {str(row.get('detected_at', ''))[:19]}"
            ):
                st.markdown(f"**Severity:** {badge}", unsafe_allow_html=True)
                st.write(f"**Alert ID:** `{row.get('alert_id', '')}`")
                st.write(f"**Description:** {row.get('description', '')}")


# ===========================================================================
# PAGE: MITRE Coverage
# ===========================================================================

elif page == "MITRE Coverage":
    st.title("MITRE ATT&CK Coverage Heatmap")

    _MITRE_NAMES: dict[str, str] = {
        "T1190": "Exploit Public-Facing App",
        "T1110": "Brute Force",
        "T1083": "File & Directory Discovery",
        "T1059": "Command & Scripting Interpreter",
        "T1046": "Network Service Discovery",
        "T1078": "Valid Accounts",
        "T1003": "OS Credential Dumping",
        "T0000": "Unknown / Unmapped",
    }

    df = mitre_coverage(DB_PATH)
    if df.empty:
        st.info("No alert data for MITRE mapping.")
    else:
        df["technique"] = df["mitre_technique_id"].map(
            lambda x: f"{x} — {_MITRE_NAMES.get(x, 'Unknown')}"
        )
        st.bar_chart(df.set_index("technique")["count"])

        st.markdown("---")
        st.subheader("Coverage Table")
        st.dataframe(
            df[["mitre_technique_id", "technique", "count"]].rename(
                columns={
                    "mitre_technique_id": "Technique ID",
                    "technique": "Technique Name",
                    "count": "Alert Count",
                }
            ),
            use_container_width=True,
        )

        total_known = len(
            [t for t in df["mitre_technique_id"] if t != "T0000"]
        )
        st.info(
            f"Coverage: {total_known} distinct MITRE techniques triggered "
            f"across {int(df['count'].sum())} alerts."
        )


# ===========================================================================
# PAGE: Approvals
# ===========================================================================

elif page == "Approvals":
    st.title("Human-in-the-Loop Approval Queue")

    pend_df = pending_approvals(DB_PATH)
    hist_df = approval_history(DB_PATH)

    st.subheader(f"Pending ({len(pend_df)})")
    if pend_df.empty:
        st.success("No pending approvals — all clear.")
    else:
        for _, row in pend_df.iterrows():
            with st.expander(
                f"Alert `{row['alert_id']}` — Action: **{row['suggested_action']}**"
            ):
                st.write(f"**Request ID:** `{row['request_id']}`")
                st.write(f"**Queued at:** {str(row.get('timestamp', ''))[:19]} UTC")
                st.write(
                    "To approve or reject this request, use the CLI:  \n"
                    f"```\npy -c \""
                    f"from guardrails.approval import ApprovalGate; "
                    f"g=ApprovalGate('data/minisoc.duckdb'); "
                    f"g.approve('{row['request_id']}', 'analyst')"
                    f"\"\n```"
                )

    st.markdown("---")
    st.subheader("Decision History")
    if hist_df.empty:
        st.info("No completed approvals yet.")
    else:
        st.dataframe(hist_df, use_container_width=True)


# ===========================================================================
# PAGE: Audit Chain
# ===========================================================================

elif page == "Audit Chain":
    st.title("Tamper-Evident Audit Log")

    chain = audit_chain_status(AUDIT_LOG)

    if chain["valid"]:
        st.success(
            f"Chain VALID — {chain['entry_count']} entries verified. "
            f"No tampering detected."
        )
    else:
        st.error(
            f"Chain INTEGRITY FAILURE at entry index {chain['broken_at']}! "
            f"The audit log may have been tampered with."
        )

    st.markdown("---")

    col_a, col_b = st.columns(2)
    col_a.metric("Total Entries", chain["entry_count"])
    col_b.metric("Integrity", "OK" if chain["valid"] else "FAIL")

    st.markdown(f"**Log file:** `{chain['log_path']}`")

    # Show raw log
    log_path = Path(AUDIT_LOG)
    if log_path.exists():
        with st.expander("View raw JSONL entries (last 20)"):
            lines = log_path.read_text(encoding="utf-8").splitlines()
            st.code("\n".join(lines[-20:]), language="json")
    else:
        st.info("Audit log file not found. Run the triage pipeline to create it.")

    st.markdown("---")
    st.markdown(
        "### How it works\n"
        "Each entry stores `SHA-256(prev_hash + canonical_payload)`.  \n"
        "Any modification to a past entry invalidates its hash **and** breaks "
        "every subsequent link — the broken index is reported immediately.  \n\n"
        "This provides **chain of custody** for all SOC decisions without a "
        "trusted third party."
    )


# ===========================================================================
# PAGE: Analyst Feedback
# ===========================================================================

elif page == "Analyst Feedback":
    st.title("Analyst Feedback Loop")

    st.markdown(
        "Flag false positives or confirm true positives so the ML model "
        "can be retrained on analyst-labelled data."
    )

    st.subheader("Submit Feedback")

    alert_df = recent_alerts(DB_PATH, limit=50)
    if alert_df.empty:
        st.warning("No alerts to review yet.")
    else:
        alert_ids = alert_df["alert_id"].tolist()
        selected_id = st.selectbox("Select alert to review", alert_ids)

        # Show selected alert details
        row = alert_df[alert_df["alert_id"] == selected_id].iloc[0]
        st.write(f"**Rule:** `{row.get('rule_id', '')}`")
        st.write(f"**Severity:** {row.get('severity', '')}")
        st.write(f"**Description:** {row.get('description', '')}")

        was_fp = st.radio(
            "Classification",
            ["True Positive (real attack)", "False Positive (benign activity)"],
        )
        comment = st.text_area("Analyst note (optional)")

        if st.button("Submit Feedback"):
            try:
                store_feedback(
                    alert_id=selected_id,
                    was_fp=(was_fp == "False Positive (benign activity)"),
                    comment=comment,
                    db_path=DB_PATH,
                )
                st.success("Feedback recorded.")
            except Exception as exc:
                st.error(f"Could not store feedback: {exc}")

    st.markdown("---")
    st.subheader("Feedback Summary")
    fb_df = feedback_summary(DB_PATH)
    if fb_df.empty:
        st.info("No feedback submitted yet.")
    else:
        fb_df["label"] = fb_df["was_fp"].map(
            {True: "False Positive", False: "True Positive"}
        )
        st.bar_chart(fb_df.set_index("label")["count"])
        total_fb = int(fb_df["count"].sum())
        fp_count = int(fb_df.loc[fb_df["was_fp"] == True, "count"].sum()) if True in fb_df["was_fp"].values else 0
        fp_rate = fp_count / total_fb if total_fb else 0
        st.metric("False Positive Rate", f"{fp_rate:.1%}")
