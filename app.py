import streamlit as st
import re
import pandas as pd
from datetime import datetime

# Set up the page
st.set_page_config(page_title="GuardianAngel DLP", layout="wide")
st.title("🛡️ GuardianAngel DLP - Data Leak Prevention System")

# Initialize session state for audit logs and alerts
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []

# Function to add a message to the audit log
def log_event(user, action, target, status, reason="None"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "Timestamp": timestamp,
        "User": user,
        "Action": action,
        "Target": target,
        "Status": status,
        "Reason": reason
    }
    st.session_state.audit_log.append(log_entry)

# Function to add a high-priority alert
def add_alert(alert_message, level="HIGH"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.alerts.append(f"[{timestamp}] {level} PRIORITY: {alert_message}")

# --- SENSITIVE DATA PATTERNS (The Detective) ---
patterns = {
    "Credit Card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "Social Security Number (SSN)": r"\b\d{3}-\d{2}-\d{4}\b",
    "Phone Number": r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Simple Password": r"(password|passwd)\s*[:=]\s*(\S+)",
    "API Key": r"\b[a-zA-Z0-9]{32,40}\b",
}

# --- MACHINE LEARNING SIMULATION (The Smart Analyst) ---
def classify_document_sensitivity(text):
    """A simple rule-based simulation of an ML model."""
    sensitive_keywords = ["confidential", "proprietary", "secret", "board meeting", 
                         "layoff", "budget", "internal only", "restricted"]
    text_lower = text.lower()
    score = 0

    # Score based on keywords
    for keyword in sensitive_keywords:
        if keyword in text_lower:
            score += 1

    # Score based on presence of any regex pattern match
    for pattern_name, pattern_regex in patterns.items():
        if re.search(pattern_regex, text):
            score += 2

    # Classify based on score
    if score >= 3:
        return "HIGH"
    elif score >= 1:
        return "MEDIUM"
    else:
        return "LOW"

# --- POLICY ENGINE (The Decision Maker) ---
def check_policy(source, content, context="email"):
    """Applies security policies to the content."""
    actions = []
    reasons = []

    # Policy 1: Check for specific sensitive data patterns
    for data_type, pattern in patterns.items():
        if re.search(pattern, content):
            actions.append("BLOCK")
            reasons.append(f"Contains {data_type}")

    # Policy 2: Check document sensitivity
    sensitivity = classify_document_sensitivity(content)
    if sensitivity == "HIGH":
        actions.append("BLOCK")
        reasons.append("Document classified as HIGH sensitivity")
    elif sensitivity == "MEDIUM":
        actions.append("ALERT")
        reasons.append("Document classified as MEDIUM sensitivity")

    # Policy 3: Context-specific rules
    if context == "email_external" and any(action in actions for action in ["BLOCK", "ALERT"]):
        reasons.append("Recipient is external")
        if "ALERT" in actions:
            actions.remove("ALERT")
            actions.append("BLOCK")

    # Policy 4: Internal share specific rules
    if context == "internal_share" and "BLOCK" in actions:
        reasons.append("File stored in insecure location")

    # Decide the final action
    final_action = "ALLOW"
    final_reason = "No policy violations detected."
    
    if "BLOCK" in actions:
        final_action = "BLOCK"
        final_reason = " | ".join(reasons)
    elif "ALERT" in actions:
        final_action = "ALERT"
        final_reason = " | ".join(reasons)

    return final_action, final_reason

# --- STREAMLIT USER INTERFACE ---
tab1, tab2, tab3, tab4 = st.tabs(["Compose Email", "Internal Shares", "Live Alerts", "Audit Log"])

with tab1:
    st.header("📧 Compose Email")
    col1, col2 = st.columns(2)
    with col1:
        user_name = st.text_input("From (User):", "john.doe@yourcompany.com")
    with col2:
        recipient_email = st.text_input("To:", "external.person@gmail.com")

    uploaded_file = st.file_uploader("Attach File", type=['txt', 'pdf', 'docx'])
    
    if st.button("Send Email"):
        if uploaded_file is not None:
            bytes_data = uploaded_file.getvalue()
            try:
                file_content = bytes_data.decode("utf-8")
            except:
                file_content = str(bytes_data)

            # Determine context
            context = "email_external" if any(domain in recipient_email for domain in ["gmail.com", "yahoo.com", "hotmail.com"]) else "email_internal"
            
            # Check policy
            action, reason = check_policy(user_name, file_content, context)
            
            # Log the event
            log_event(user_name, "Email Send", f"to {recipient_email}", action, reason)
            
            # Show result
            if action == "BLOCK":
                st.error(f"🚫 BLOCKED! Your message was not sent. Reason: {reason}")
            elif action == "ALERT":
                st.warning(f"⚠️  Warning! Message was sent but an alert was triggered. Reason: {reason}")
            else:
                st.success("✅ Message Sent Successfully!")
        else:
            st.warning("Please attach a file first.")

with tab2:
    st.header("📁 Internal File Share Monitor")
    st.caption("Scanning shared network drives for misplaced sensitive files")
    
    # Simulated shared files database
    shared_files = {
        "\\shared\\public\\budget_Q4.txt": "Confidential Q4 Budget Report\nRevenue: $5,000,000\nProfit: $1,200,000\nSSN for verification: 123-45-6789",
        "\\shared\\projects\\alpha\\design.docx": "Project Alpha Design Document\nProprietary technology specifications\nAPI Key: abc123def456ghi789jkl012mno345pqr678",
        "\\shared\\hr\\employees.csv": "Name,Department,Salary\nJohn Doe,Engineering,85000\nJane Smith,Marketing,75000",
        "\\shared\\public\\lunch_menu.txt": "Monday: Pizza\nTuesday: Sandwiches\nWednesday: Salad"
    }
    
    if st.button("🔍 Run Scheduled Share Scan"):
        st.info("Scanning internal file shares...")
        
        for file_path, file_content in shared_files.items():
            # Check policy for internal share context
            action, reason = check_policy("System", file_content, "internal_share")
            
            # Log the finding
            log_event("System", "File Share Scan", file_path, action, reason)
            
            # Create alert for problematic files
            if action == "BLOCK":
                add_alert(f"Sensitive file in insecure location: {file_path}. Reason: {reason}")
                st.error(f"🚫 {file_path} - {reason}")
            elif action == "ALERT":
                add_alert(f"Potensitive file found: {file_path}. Reason: {reason}")
                st.warning(f"⚠️  {file_path} - {reason}")
            else:
                st.success(f"✅ {file_path} - No issues found")
        
        st.success("Share scan completed. Check the Alerts tab for details.")

with tab3:
    st.header("🚨 Live Security Alert Dashboard")
    st.caption("Security team monitor this in real-time")
    
    if not st.session_state.alerts:
        st.info("No active alerts. Everything is quiet!")
    else:
        for alert in reversed(st.session_state.alerts):
            if "BLOCKED" in alert or "Sensitive file" in alert:
                st.error(alert)
            elif "Warning" in alert or "Potensitive" in alert:
                st.warning(alert)
            else:
                st.info(alert)

with tab4:
    st.header("📊 Audit Log")
    st.caption("History of all security events")
    
    if st.session_state.audit_log:
        log_df = pd.DataFrame(st.session_state.audit_log)
        st.dataframe(log_df, use_container_width=True)
        
        # Add export option
        csv = log_df.to_csv(index=False)
        st.download_button(
            label="Export Log as CSV",
            data=csv,
            file_name="dlp_audit_log.csv",
            mime="text/csv",
        )
    else:
        st.info("No events logged yet.")

# Footer
st.markdown("---")
st.caption("GuardianAngel DLP v2.0 - Protecting your data across all channels")