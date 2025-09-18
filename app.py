# ------------------------------
# Policy Engine
# ------------------------------
class PolicyEngine:
    def __init__(self):
        # Default rules (can be later customized in Policy Management tab)
        self.rules = {
            "SSN": "Block",
            "Credit Card": "Quarantine",
            "API Key": "Block",
            "AWS Key": "Block",
            "Password": "Alert",
            "Email": "Monitor"
        }

    def evaluate(self, patterns_found, risk_level):
        """Return action based on detected patterns + risk level"""
        actions = []
        for pattern in patterns_found.keys():
            if pattern in self.rules:
                actions.append(self.rules[pattern])
        if not actions and risk_level == "Low":
            return "Allow"
        elif not actions and risk_level == "Medium":
            return "Quarantine"
        elif not actions and risk_level == "High":
            return "Block"
        return max(actions, key=actions.count)

# Initialize policy engine
policy_engine = PolicyEngine()
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import re
import time
import io
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from PIL import Image
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Conv1D, GlobalMaxPooling1D, Embedding, Dropout
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
try:
    import lime
    from lime.lime_text import LimeTextExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
import smtplib
from email.mime.text import MIMEText
import random
import docx
import os
import json
import PyPDF2
import warnings
warnings.filterwarnings('ignore')
try:
    from transformers import pipeline
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

# SMTP configuration (update these with your details or via env)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'vishnupriya.a2023@vitstudent.ac.in')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD', 'xbll army oyua beke')

# users DB file (simple JSON for demo)
USERS_DB = os.path.join(os.getcwd(), "users.json")
if not os.path.exists(USERS_DB):
    with open(USERS_DB, "w") as f:
        json.dump({}, f)

# DLP data storage
DLP_DATA_FILE = os.path.join(os.getcwd(), "dlp_data.json")
if not os.path.exists(DLP_DATA_FILE):
    with open(DLP_DATA_FILE, "w") as f:
        json.dump({
            "scans": [],
            "violations": [],
            "blocked_attempts": [],
            "risk_distribution": {"High": 0, "Medium": 0, "Low": 0},
            "detection_stats": {pattern: 0 for pattern in ['SSN', 'Credit Card', 'Phone', 'Email', 'API Key', 'AWS Key', 'Password']},
            "email_scans": []
        }, f)

def load_dlp_data():
    with open(DLP_DATA_FILE, "r") as f:
        return json.load(f)

def save_dlp_data(data):
    with open(DLP_DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)
class DLPSystem:
    def __init__(self):
        # Sensitive data patterns (regex)
        self.patterns = {
            'SSN': r'(\d{3}-\d{2}-\d{4})',
            'Credit Card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            'Phone': r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'API Key': r'\b[A-Za-z0-9]{32}\b',
            'AWS Key': r'\bAKIA[0-9A-Z]{16}\b',
            'Password': r'\b(?:password|passwd|pwd)[:=]\s*([\w@#$%^&*]+)'
        }
        self.zero_shot = False
        self.zero_shot_classifier = None
        self.zero_shot_labels = list(self.patterns.keys())

    def get_zero_shot_classifier(self):
        if self.zero_shot_classifier is None and HF_AVAILABLE and self.zero_shot:
            try:
                # Use device=-1 for CPU, avoids meta tensor errors
                self.zero_shot_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=-1)
            except Exception as e:
                st.error(f"Zero-shot pipeline error: {e}")
                self.zero_shot_classifier = None
        return self.zero_shot_classifier

def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    import json, os
    USERS_DB = os.path.join(os.getcwd(), "users.json")
    if not os.path.exists(USERS_DB):
        with open(USERS_DB, "w") as f:
            json.dump({}, f)
    with open(USERS_DB, "r") as f:
        return json.load(f)

def save_users(users):
    import json, os
    USERS_DB = os.path.join(os.getcwd(), "users.json")
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=4)

# Ensure proper usage:
def send_verification_email(email: str, code: int) -> bool:
    """Send OTP via SMTP. Returns True on success, False on failure."""
    subject = "SecureDLP Verification Code"
    body = f"Your SecureDLP verification code is: {code}"
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, [email], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        st.error(f"Failed to send verification email: {e}")
        return False

# Set page configuration
st.set_page_config(
    page_title="SecureDLP - Data Leak Prevention System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {font-size: 3rem; color: #1f77b4; text-align: center;}
    .sub-header {font-size: 1.5rem; color: #2ca02c; border-bottom: 2px solid #eee; padding-bottom: 0.3rem;}
    .success-box {background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px; padding: 15px; margin: 10px 0;}
    .alert-box {background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; padding: 15px; margin: 10px 0;}
    .warning-box {background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 10px 0;}
    .info-box {background-color: #d1ecf1; border: 1px solid #bee5eb; border-radius: 5px; padding: 15px; margin: 10px 0;}
    .metric-card {background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin: 10px 0; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);}
    .stButton>button {width: 100%;}
</style>
""", unsafe_allow_html=True)

# Initialize session state keys used by auth flow
if 'auth_page' not in st.session_state:
    st.session_state.auth_page = "signup"  # options: signup, login, verify, app
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'verification_sent' not in st.session_state:
    st.session_state.verification_sent = False
if 'verification_code' not in st.session_state:
    st.session_state.verification_code = None
if 'pending_user' not in st.session_state:
    st.session_state.pending_user = None
if 'ml_model' not in st.session_state:
    st.session_state.ml_model = None
if 'vectorizer' not in st.session_state:
    st.session_state.vectorizer = None

class DLPSystem:
    def __init__(self):
        # Sensitive data patterns (regex)
        self.patterns = {
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Credit Card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            'Phone': r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'API Key': r'\b[A-Za-z0-9]{32}\b',
            'AWS Key': r'\bAKIA[0-9A-Z]{16}\b',
            'Password': r'\b(password|passwd|pwd)[:=]\s*[\w@#$%^&*]+\b'
        }
        self.zero_shot = False
        self.zero_shot_classifier = None
        self.zero_shot_labels = list(self.patterns.keys())

    
    def extract_text_from_file(self, uploaded_file):
        file_type = uploaded_file.type
        text = ""
        try:
            if file_type == "text/plain":
                text = str(uploaded_file.read(), "utf-8")
            elif file_type == "application/pdf":
                pdf_reader = PyPDF2.PdfReader(uploaded_file)
                for page in pdf_reader.pages:
                    text += (page.extract_text() or "") + "\n"
            elif file_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                doc = docx.Document(io.BytesIO(uploaded_file.read()))
                for para in doc.paragraphs:
                    text += para.text + "\n"
            else:
                text = str(uploaded_file.read(), "utf-8", errors='ignore')
        except Exception as e:
            st.error(f"Error reading file: {e}")
        return text
    
    def get_zero_shot_classifier(self):
        if self.zero_shot_classifier is None and HF_AVAILABLE:
            try:
                self.zero_shot_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=-1)
            except Exception as e:
                st.error(f"Zero-shot pipeline error: {e}")
                self.zero_shot_classifier = None
        return self.zero_shot_classifier

    def check_sensitive_data(self, text):
        results = {
            'sensitive': False,
            'patterns_found': {},
            'ml_score': 0,
            'risk_level': 'Low',
            'explanation': None
        }
        for pattern_name, pattern in self.patterns.items():
            # Only extract and show the sensitive value (group 1) for SSN and Password
            if pattern_name in ['SSN', 'Password']:
                matches = re.findall(pattern, text, re.IGNORECASE)
                results['patterns_found'][pattern_name] = [m.strip() for m in matches if m.strip()]
                if matches:
                    results['sensitive'] = True
            else:
                # For other patterns, skip display (or keep for future expansion)
                results['patterns_found'][pattern_name] = []
        # Zero-shot prediction
        if st.session_state.get('use_zero_shot', False) and HF_AVAILABLE and self.zero_shot and text.strip():
            try:
                classifier = self.get_zero_shot_classifier()
                if classifier is not None:
                    candidate_labels = self.zero_shot_labels
                    zs_result = classifier(text, candidate_labels)
                    scores = dict(zip(zs_result['labels'], zs_result['scores']))
                    # Find highest scoring label
                    best_label = zs_result['labels'][0]
                    best_score = zs_result['scores'][0]
                    results['ml_score'] = best_score
                    if best_score > 0.7:
                        results['risk_level'] = 'High'
                    elif best_score > 0.4:
                        results['risk_level'] = 'Medium'
                    else:
                        results['risk_level'] = 'Low'
                    results['explanation'] = scores
                    if best_score > 0.4:
                        results['sensitive'] = True
                        results['patterns_found'][best_label] = [text]
                else:
                    results['explanation'] = "Zero-shot pipeline not available."
            except Exception as e:
                results['explanation'] = f"Zero-shot error: {e}"
        # ML prediction (custom trained model)
        elif st.session_state.ml_model and text.strip():
            try:
                if st.session_state.get('use_cnn', False):
                    tokenizer = st.session_state.tokenizer
                    X_seq = tokenizer.texts_to_sequences([text])
                    X_pad = pad_sequences(X_seq, maxlen=50)
                    ml_score = float(st.session_state.ml_model.predict(X_pad)[0][0])
                else:
                    vectorizer = st.session_state.vectorizer
                    X = vectorizer.transform([text]).toarray()
                    ml_score = st.session_state.ml_model.predict_proba(X)[0][1]
                results['ml_score'] = ml_score
                if ml_score > 0.7 or results['sensitive']:
                    results['risk_level'] = 'High'
                elif ml_score > 0.4:
                    results['risk_level'] = 'Medium'
                # LIME explanation
                if LIME_AVAILABLE and st.session_state.get('use_cnn', False):
                    class_names = ['Normal', 'Sensitive']
                    explainer = LimeTextExplainer(class_names=class_names)
                    def predict_fn(texts):
                        X_seq = tokenizer.texts_to_sequences(texts)
                        X_pad = pad_sequences(X_seq, maxlen=50)
                        preds = st.session_state.ml_model.predict(X_pad)
                        return np.hstack([1-preds, preds])
                    exp = explainer.explain_instance(text, predict_fn, num_features=6)
                    results['explanation'] = exp.as_list()
            except Exception as e:
                results['explanation'] = f"Explanation error: {e}"
        return results
    
    def generate_verification_code(self, email):
        code = random.randint(100000, 999999)
        st.session_state.verification_code = code
        st.session_state.user_email = email
        # Try to send using the helper; if fails, user will see an error
        sent = send_verification_email(email, code)
        if sent:
            st.info(f"Verification code sent to {email}")
        return code
    
    def verify_code(self, input_code):
        return input_code == st.session_state.verification_code
    
    def log_scan_result(self, filename, file_type, file_size, risk_level, patterns_found, action_taken):
        """Log file scan results to the data store"""
        dlp_data = load_dlp_data()
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "file_type": file_type,
            "file_size": file_size,
            "risk_level": risk_level,
            "patterns_found": patterns_found,
            "action_taken": action_taken,
            "user": st.session_state.pending_user
        }
        dlp_data["scans"].append(scan_record)
        
        # Update risk distribution
        dlp_data["risk_distribution"][risk_level] += 1
        
        # Update detection statistics
        for pattern in patterns_found:
            if pattern in dlp_data["detection_stats"]:
                dlp_data["detection_stats"][pattern] += len(patterns_found[pattern])
        
        # If action was block or quarantine, log as violation
        if action_taken in ["Block transmission", "Quarantine file"]:
            violation_record = {
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "risk_level": risk_level,
                "patterns_found": patterns_found,
                "action_taken": action_taken,
                "user": st.session_state.pending_user
            }
            dlp_data["violations"].append(violation_record)
            
            if action_taken == "Block transmission":
                dlp_data["blocked_attempts"].append(violation_record)
        
        save_dlp_data(dlp_data)
    
    def log_email_scan(self, recipient, subject, risk_level, patterns_found, action_taken):
        """Log email scan results to the data store"""
        dlp_data = load_dlp_data()
        email_record = {
            "timestamp": datetime.now().isoformat(),
            "sender": st.session_state.pending_user,
            "recipient": recipient,
            "subject": subject,
            "risk_level": risk_level,
            "patterns_found": patterns_found,
            "action_taken": action_taken
        }
        dlp_data["email_scans"].append(email_record)
        save_dlp_data(dlp_data)

# Initialize DLP system
dlp_system = DLPSystem()

# App title and description
st.markdown('<h1 class="main-header">🔒 SecureDLP</h1>', unsafe_allow_html=True)
st.markdown("### Automated Data Leak Prevention System")
st.markdown("Protect your organization's sensitive data with AI-powered scanning and detection")

# Sidebar for navigation (we'll use it for auth controls)
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/3063/3063188.png", width=100)
st.sidebar.title("Navigation")

# Initialize ML model if not already done

# ML Training UI (sidebar)
dlp_system.zero_shot = HF_AVAILABLE
st.session_state.use_zero_shot = HF_AVAILABLE

# ------------------------------
# AUTH: Signup / Login / Verify
# ------------------------------
st.sidebar.markdown("---")
st.sidebar.subheader("Account")

# Sidebar controls to switch pages
if st.session_state.auth_page != "app":
    if st.sidebar.button("Go to Signup"):
        st.session_state.auth_page = "signup"
        st.rerun()
    if st.sidebar.button("Go to Login"):
        st.session_state.auth_page = "login"
        st.rerun()

# SIGNUP page
if st.session_state.auth_page == "signup":
    st.sidebar.markdown("### Create Account")
    new_email = st.sidebar.text_input("Email (must end with @vitstudent.ac.in)", key="signup_email")
    new_password = st.sidebar.text_input("Password", type="password", key="signup_password")
    if st.sidebar.button("Sign Up"):
        if not new_email or not new_password:
            st.sidebar.error("Email and password are required")
        elif not new_email.endswith("@vitstudent.ac.in"):
            st.sidebar.error("Only @vitstudent.ac.in emails are allowed")
        else:
            users = load_users()
            if new_email in users:
                st.sidebar.error("Account already exists. Please login.")
            else:
                users[new_email] = {"password": hash_password(new_password)}
                save_users(users)
                st.sidebar.success("Account created. Please go to Login.")
                st.session_state.auth_page = "login"
                st.rerun()

# LOGIN page
elif st.session_state.auth_page == "login":
    st.sidebar.markdown("### Login (Password → OTP)")
    login_email = st.sidebar.text_input("Email", key="login_email")
    login_password = st.sidebar.text_input("Password", type="password", key="login_password")

    if not st.session_state.verification_sent:
        if st.sidebar.button("Send Verification Code"):
            if not login_email or not login_password:
                st.sidebar.error("Provide email and password")
            elif not login_email.endswith("@vitstudent.ac.in"):
                st.sidebar.error("Only @vitstudent.ac.in emails are allowed")
            else:
                users = load_users()
                if login_email not in users:
                    st.sidebar.error("No account found. Please sign up.")
                elif users[login_email]["password"] != hash_password(login_password):
                    st.sidebar.error("Incorrect password")
                else:
                    # Password correct → send OTP
                    code = random.randint(100000, 999999)
                    st.session_state.verification_code = code
                    st.session_state.pending_user = login_email
                    sent = send_verification_email(login_email, code)
                    if sent:
                        st.session_state.verification_sent = True
                        st.sidebar.success("Verification code sent to your email")
                    else:
                        st.sidebar.error("Failed to send verification code. Check SMTP settings.")
    else:
        # OTP verification step
        st.sidebar.markdown("### Enter Verification Code")
        otp_input = st.sidebar.text_input("Verification Code", type="password", key="otp_input")
        if st.sidebar.button("Verify Code"):
            if otp_input and otp_input.isdigit() and int(otp_input) == st.session_state.verification_code:
                st.session_state.authenticated = True
                st.session_state.verification_sent = False
                st.session_state.verification_code = None
                st.session_state.auth_page = "app"
                st.sidebar.success("Authentication successful!")
                st.rerun()
            else:
                st.sidebar.error("Invalid verification code")

# If user is authenticated show app, else show small preview in main area
if not st.session_state.authenticated:
    st.warning("Please sign up or log in using the sidebar (must be @vitstudent.ac.in) to access SecureDLP.")
    # Demo preview content for unauthenticated users
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 🔍 Content Scanning")
        st.markdown("""
        - Real-time file analysis
        - Email content inspection
        - Network traffic monitoring
        """)
    with col2:
        st.markdown("### 🤖 AI-Powered Detection")
        st.markdown("""
        - Machine learning models
        - Pattern recognition
        - Behavioral analysis
        """)
    with col3:
        st.markdown("### 📊 Policy Enforcement")
        st.markdown("""
        - Customizable rules
        - Automated actions
        - Comprehensive logging
        """)
    st.markdown("---")
    st.markdown("### How It Works")
    st.markdown("""
    1. *Sign up* with your @vitstudent.ac.in email
    2. *Login* with password, then verify the OTP sent to your email
    3. *Use* the SecureDLP dashboards and scanners
    """)
else:
    # ------------------------------
    # MAIN APP (user authenticated)
    # ------------------------------
    menu = st.sidebar.selectbox("Menu", ["Dashboard", "File Scanner", "Email Protection", "Policy Management", "Reports & Analytics"])

    if menu == "Dashboard":
        st.markdown('<p class="sub-header">System Dashboard</p>', unsafe_allow_html=True)
        dlp_data = load_dlp_data()
        # Calculate metrics
        total_scans = len(dlp_data["scans"])
        today = datetime.now().date()
        today_scans = sum(datetime.fromisoformat(scan["timestamp"]).date() == today for scan in dlp_data["scans"])
        total_violations = len(dlp_data["violations"])
        today_violations = sum(datetime.fromisoformat(v["timestamp"]).date() == today for v in dlp_data["violations"])
        total_blocked = len(dlp_data["blocked_attempts"])
        today_blocked = sum(datetime.fromisoformat(b["timestamp"]).date() == today for b in dlp_data["blocked_attempts"])
        # Use both file and email violations for audit log
        all_violations = list(dlp_data["violations"])
        for e in dlp_data.get("email_scans", []):
            if e.get("action_taken") == "Blocked":
                all_violations.append({
                    "timestamp": e["timestamp"],
                    "risk_level": e.get("risk_level", "Unknown"),
                    "patterns_found": e.get("patterns_found", {}),
                    "action_taken": e.get("action_taken", "Unknown"),
                    "user": e.get("sender", "Unknown")
                })
        if all_violations:
            recent_violations = sorted(all_violations, key=lambda x: x["timestamp"], reverse=True)[:5]
            alert_data = pd.DataFrame([{
                'Time': datetime.fromisoformat(v["timestamp"]).strftime('%Y-%m-%d %H:%M'),
                'Severity': v["risk_level"],
                'Type': ', '.join([k for k, v2 in v["patterns_found"].items() if v2][:2]) + ('...' if len([k for k, v2 in v["patterns_found"].items() if v2]) > 2 else ''),
                'Action': v["action_taken"],
                'User': v.get("user", "Unknown")
            } for v in recent_violations])
            st.dataframe(alert_data, use_container_width=True)
        else:
            st.info("No violations detected yet.")
        # Risk distribution chart
        st.markdown("### Risk Distribution")
        risk_levels = {"High": 0, "Medium": 0, "Low": 0}
        for scan in dlp_data["scans"]:
            rl = scan.get("risk_level", "Low")
            if rl in risk_levels:
                risk_levels[rl] += 1
        for email in dlp_data.get("email_scans", []):
            rl = email.get("risk_level", "Low")
            if rl in risk_levels:
                risk_levels[rl] += 1
        risk_data = pd.DataFrame({
            'Risk Level': list(risk_levels.keys()),
            'Count': list(risk_levels.values())
        })
        risk_data['Count'] = risk_data['Count'].fillna(0).astype(int)
        if risk_data['Count'].sum() > 0:
            fig, ax = plt.subplots()
            ax.pie(risk_data['Count'], labels=risk_data['Risk Level'], autopct='%1.1f%%')
            ax.set_title('Sensitivity Distribution')
            st.pyplot(fig)
        else:
            st.info("No risk data to display yet.")
    
    elif menu == "File Scanner":
        st.markdown('<p class="sub-header">File Content Scanner</p>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload a file for scanning", 
            type=['txt', 'pdf', 'docx', 'doc', 'csv', 'xlsx', 'pptx']
        )
        if uploaded_file is not None:
            file_details = {
                "Filename": uploaded_file.name,
                "File size": f"{uploaded_file.size / 1024:.2f} KB",
                "File type": uploaded_file.type
            }
            st.write(file_details)
            with st.spinner("Scanning file for sensitive data..."):
                text = dlp_system.extract_text_from_file(uploaded_file)
                results = dlp_system.check_sensitive_data(text)
                if results['sensitive'] or results['ml_score'] > 0.4:
                    st.markdown('<div class="alert-box">', unsafe_allow_html=True)
                    st.error("⚠ Sensitive content detected!")
                    for pattern in ['SSN', 'Password']:
                        matches = results['patterns_found'].get(pattern, [])
                        if matches:
                            st.write(f"{pattern} detected:** {', '.join(matches[:3])}{'...' if len(matches) > 3 else ''}")
                    st.write(f"Confidence: {results['ml_score']:.2%}")
                    st.write(f"Risk Level: {results['risk_level']}")
                    # Automatic Policy Decision
                    decision = policy_engine.evaluate(results['patterns_found'], results['risk_level'])
                    st.warning(f"Policy Decision: *{decision}*")
                    if st.button("Apply Action"):
                        st.success(f"Action applied: {decision}")
                        st.info(f"Incident logged at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="success-box">', unsafe_allow_html=True)
                    st.success("✅ No sensitive content detected")
                    st.write(f"Confidence: {results['ml_score']:.2%}")
                    st.write(f"Risk Level: {results['risk_level']}")
                    dlp_system.log_scan_result(
                        uploaded_file.name, 
                        uploaded_file.type, 
                        f"{uploaded_file.size / 1024:.2f} KB",
                        results['risk_level'],
                        results['patterns_found'],
                        "No action needed"
                    )
                    st.markdown('</div>', unsafe_allow_html=True)
                if text:
                    with st.expander("View extracted text"):
                        st.text(text[:500] + "..." if len(text) > 500 else text)
    
    elif menu == "Email Protection":
        st.markdown('<p class="sub-header">Email Content Protection</p>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Compose Email")
            recipient = st.text_input("To")
            subject = st.text_input("Subject")
            email_body = st.text_area("Message", height=200)
            email_attachment = st.file_uploader("Attach file", key="email_attachment")
            if st.button("Send Email"):
                email_sent = False
                if not recipient:
                    st.error("Recipient email is required")
                elif not recipient.endswith("@vitstudent.ac.in"):
                    st.error("Only @vitstudent.ac.in recipient emails are allowed")
                else:
                    content_to_check = f"{subject} {email_body}"
                    if email_attachment:
                        content_to_check += dlp_system.extract_text_from_file(email_attachment)
                    results = dlp_system.check_sensitive_data(content_to_check)
                    sensitive_found = any(matches for matches in results['patterns_found'].values())
                    if sensitive_found:
                        st.error("Email blocked: Sensitive content detected")
                        for pattern, matches in results['patterns_found'].items():
                            if matches:
                                st.write(f"{pattern} detected:** {', '.join(matches[:2])}{'...' if len(matches) > 2 else ''}")
                        dlp_system.log_email_scan(
                            recipient, subject, results['risk_level'], 
                            results['patterns_found'], "Blocked"
                        )
                    elif results['ml_score'] > 0.4:
                        st.error("Email blocked: ML model flagged sensitive content")
                        dlp_system.log_email_scan(
                            recipient, subject, results['risk_level'], 
                            results['patterns_found'], "Blocked"
                        )
                    else:
                        st.success("Email sent successfully!")
                        dlp_system.log_email_scan(
                            recipient, subject, results['risk_level'], 
                            results['patterns_found'], "Allowed"
                        )
        with col2:
            st.subheader("Outbound Policy")
            st.markdown("""
            - *High Risk:* Block transmission
            - *Medium Risk:* Quarantine for review
            - *Low Risk:* Allow with logging
            
            *Protected Data Types:*
            - Social Security Numbers
            - Credit Card Numbers
            - API Keys & Secrets
            - Passwords
            - Personal Identifiable Information
            """)
            st.subheader("Recent Scans")
            dlp_data = load_dlp_data()
            if dlp_data["email_scans"]:
                recent_scans = sorted(dlp_data["email_scans"], 
                                     key=lambda x: x["timestamp"], reverse=True)[:5]
                scan_data = pd.DataFrame([{
                    'Time': datetime.fromisoformat(s["timestamp"]).strftime('%H:%M %p'),
                    'Sender': s.get("sender", "Unknown"),
                    'To': s.get("recipient", "Unknown"),
                    'Status': s.get("action_taken", "Unknown"),
                    'Reason': ', '.join([k for k, v in s.get("patterns_found", {}).items() if v]) or 'No issues'
                } for s in recent_scans])
                st.dataframe(scan_data, use_container_width=True)
            else:
                st.info("No email scans recorded yet.")
    
    elif menu == "Policy Management":
        st.markdown('<p class="sub-header">Policy Management</p>', unsafe_allow_html=True)
        tab1, tab2, tab3 = st.tabs(["Data Patterns", "Action Rules", "User Groups"])
        with tab1:
            st.subheader("Sensitive Data Patterns")
            pattern_df = pd.DataFrame([
                {"Pattern": "SSN", "Regex": dlp_system.patterns['SSN'], "Status": "Active"},
                {"Pattern": "Credit Card", "Regex": dlp_system.patterns['Credit Card'], "Status": "Active"},
                {"Pattern": "API Key", "Regex": dlp_system.patterns['API Key'], "Status": "Active"},
                {"Pattern": "AWS Key", "Regex": dlp_system.patterns['AWS Key'], "Status": "Active"},
                {"Pattern": "Password", "Regex": dlp_system.patterns['Password'], "Status": "Active"},
                {"Pattern": "Email", "Regex": dlp_system.patterns['Email'], "Status": "Monitoring"},
            ])
            st.dataframe(pattern_df, use_container_width=True)
            with st.expander("Add New Pattern"):
                new_pattern_name = st.text_input("Pattern Name")
                new_pattern_regex = st.text_input("Regular Expression")
                if st.button("Add Pattern"):
                    if new_pattern_name and new_pattern_regex:
                        st.success(f"Pattern '{new_pattern_name}' added")
                    else:
                        st.error("Both fields are required")
        with tab2:
            st.subheader("Policy Actions")
            action_df = pd.DataFrame([
                {"Data Type": "SSN", "Action": "Block", "Channel": "All", "User Group": "All"},
                {"Data Type": "Credit Card", "Action": "Quarantine", "Channel": "Email", "User Group": "All"},
                {"Data Type": "API Key", "Action": "Block", "Channel": "All", "User Group": "All"},
                {"Data Type": "Password", "Action": "Alert", "Channel": "File Share", "User Group": "All"},
            ])
            st.dataframe(action_df, use_container_width=True)
            with st.expander("Create New Policy"):
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    policy_data_type = st.selectbox("Data Type", list(dlp_system.patterns.keys()))
                with col2:
                    policy_action = st.selectbox("Action", ["Block", "Quarantine", "Alert", "Monitor"])
                with col3:
                    policy_channel = st.selectbox("Channel", ["All", "Email", "File Share", "Web"])
                with col4:
                    policy_group = st.selectbox("User Group", ["All", "HR", "Finance", "Engineering"])
                if st.button("Create Policy"):
                    st.success("Policy created successfully")
        with tab3:
            st.subheader("User Groups & Permissions")
            group_df = pd.DataFrame([
                {"Group": "HR", "Members": "12", "Policies": "5", "Restrictions": "SSN access"},
                {"Group": "Finance", "Members": "8", "Policies": "7", "Restrictions": "Credit card processing"},
                {"Group": "Engineering", "Members": "25", "Policies": "4", "Restrictions": "API key management"},
                {"Group": "Executive", "Members": "5", "Policies": "2", "Restrictions": "None"},
            ])
            st.dataframe(group_df, use_container_width=True)
    
    elif menu == "Reports & Analytics":
        st.markdown('<p class="sub-header">Reports & Analytics</p>', unsafe_allow_html=True)
        # Always reload real-time data
        dlp_data = load_dlp_data()
        # Metrics
        total_scans = len(dlp_data["scans"]) + len(dlp_data.get("email_scans", []))
        total_violations = len(dlp_data["violations"]) + sum(1 for e in dlp_data.get("email_scans", []) if e.get("action_taken") == "Blocked")
        total_blocked = len(dlp_data["blocked_attempts"]) + sum(1 for e in dlp_data.get("email_scans", []) if e.get("action_taken") == "Blocked")
        st.metric("Total Scans", total_scans)
        st.metric("Total Violations", total_violations)
        st.metric("Total Blocked", total_blocked)
        # Detection Statistics by Month
        detection_by_month = {}
        for scan in dlp_data["scans"]:
            month = datetime.fromisoformat(scan["timestamp"]).strftime('%b')
            if month not in detection_by_month:
                detection_by_month[month] = {pattern: 0 for pattern in dlp_system.patterns.keys()}
            for pattern in scan["patterns_found"]:
                detection_by_month[month][pattern] += len(scan["patterns_found"][pattern])
        # Include email scans
        for email in dlp_data.get("email_scans", []):
            month = datetime.fromisoformat(email["timestamp"]).strftime('%b')
            if month not in detection_by_month:
                detection_by_month[month] = {pattern: 0 for pattern in dlp_system.patterns.keys()}
            for pattern in email["patterns_found"]:
                detection_by_month[month][pattern] += len(email["patterns_found"][pattern])
        # Chart
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Detection Statistics")
            if detection_by_month:
                months = list(detection_by_month.keys())
                detection_data = pd.DataFrame({
                    'Month': months,
                    **{pattern: [detection_by_month[m].get(pattern, 0) for m in months] for pattern in dlp_system.patterns.keys()}
                })
                fig, ax = plt.subplots(figsize=(8, 5))
                detection_data.set_index('Month').plot(kind='bar', ax=ax)
                ax.set_title('Sensitive Data Detections by Type')
                ax.set_ylabel('Count')
                plt.xticks(rotation=45)
                st.pyplot(fig)
            else:
                st.info("No detection data available yet.")
        # Risk Trend by Week
        with col2:
            st.subheader("Risk Trend")
            risk_by_week = {}
            for scan in dlp_data["scans"]:
                week_num = datetime.fromisoformat(scan["timestamp"]).isocalendar()[1]
                if week_num not in risk_by_week:
                    risk_by_week[week_num] = {"High": 0, "Medium": 0, "Low": 0}
                risk_by_week[week_num][scan["risk_level"]] += 1
            for email in dlp_data.get("email_scans", []):
                week_num = datetime.fromisoformat(email["timestamp"]).isocalendar()[1]
                if week_num not in risk_by_week:
                    risk_by_week[week_num] = {"High": 0, "Medium": 0, "Low": 0}
                risk_by_week[week_num][email["risk_level"]] += 1
            if risk_by_week:
                weeks = sorted(risk_by_week.keys())
                risk_data = pd.DataFrame({
                    'Week': weeks,
                    'High': [risk_by_week[w]['High'] for w in weeks],
                    'Medium': [risk_by_week[w]['Medium'] for w in weeks],
                    'Low': [risk_by_week[w]['Low'] for w in weeks]
                })
                fig, ax = plt.subplots(figsize=(8, 5))
                ax.plot(risk_data['Week'], risk_data['High'], marker='o', label='High', linewidth=2)
                ax.plot(risk_data['Week'], risk_data['Medium'], marker='s', label='Medium', linewidth=2)
                ax.plot(risk_data['Week'], risk_data['Low'], marker='^', label='Low', linewidth=2)
                ax.set_title('Risk Level Trend Over Time')
                ax.set_xlabel('Week')
                ax.set_ylabel('Count')
                ax.legend()
                ax.grid(True, linestyle='--', alpha=0.7)
                st.pyplot(fig)
            else:
                st.info("No risk data available yet.")
        # Recent Audit Log Table
        st.subheader("Recent Audit Log")
        all_violations = list(dlp_data["violations"])
        for e in dlp_data.get("email_scans", []):
            if e.get("action_taken") == "Blocked":
                all_violations.append({
                    "timestamp": e["timestamp"],
                    "risk_level": e.get("risk_level", "Unknown"),
                    "patterns_found": e.get("patterns_found", {}),
                    "action_taken": e.get("action_taken", "Unknown"),
                    "user": e.get("sender", "Unknown"),
                    "type": "Email"
                })
        if all_violations:
            recent_violations = sorted(all_violations, key=lambda x: x["timestamp"], reverse=True)[:10]
            audit_data = pd.DataFrame([{
                'Time': datetime.fromisoformat(v["timestamp"]).strftime('%Y-%m-%d %H:%M'),
                'Severity': v["risk_level"],
                'Type': ', '.join([k for k, v2 in v["patterns_found"].items() if v2][:2]) + ('...' if len([k for k, v2 in v["patterns_found"].items() if v2]) > 2 else ''),
                'Action': v["action_taken"],
                'User': v.get("user", "Unknown"),
                'Channel': v.get("type", "File")
            } for v in recent_violations])
            st.dataframe(audit_data, use_container_width=True)
        else:
            st.info("No audit log entries yet.")
        # Custom Report
        st.subheader("Generate Custom Report")
        report_range = st.selectbox("Time Range", ["Last 7 days", "Last 30 days", "Last quarter", "Last year"])
        report_type = st.multiselect("Data Types", list(dlp_system.patterns.keys()), default=list(dlp_system.patterns.keys())[:3])
        if st.button("Generate Report"):
            with st.spinner("Generating report..."):
                dlp_data = load_dlp_data()
                now = datetime.now()
                if report_range == "Last 7 days":
                    cutoff_date = now - timedelta(days=7)
                elif report_range == "Last 30 days":
                    cutoff_date = now - timedelta(days=30)
                elif report_range == "Last quarter":
                    cutoff_date = now - timedelta(days=90)
                else:
                    cutoff_date = now - timedelta(days=365)
                filtered_scans = [scan for scan in dlp_data["scans"] if datetime.fromisoformat(scan["timestamp"]) >= cutoff_date]
                filtered_emails = [e for e in dlp_data.get("email_scans", []) if datetime.fromisoformat(e["timestamp"]) >= cutoff_date]
                filtered_violations = [v for v in dlp_data["violations"] if datetime.fromisoformat(v["timestamp"]) >= cutoff_date]
                filtered_email_violations = [e for e in filtered_emails if e.get("action_taken") == "Blocked"]
                # Create report content
                report_content = f"SecureDLP Report - {report_range}\n"
                report_content += f"Generated on: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
                report_content += f"Total scans: {len(filtered_scans) + len(filtered_emails)}\n"
                report_content += f"Total violations: {len(filtered_violations) + len(filtered_email_violations)}\n"
                report_content += f"Data types included: {', '.join(report_type)}\n\n"
                # Add detection statistics
                report_content += "Detection Statistics:\n"
                for pattern in report_type:
                    count = sum(len(scan["patterns_found"].get(pattern, [])) for scan in filtered_scans)
                    count += sum(len(email["patterns_found"].get(pattern, [])) for email in filtered_emails)
                    report_content += f"- {pattern}: {count} detections\n"
                # Add risk distribution
                risk_dist = {"High": 0, "Medium": 0, "Low": 0}
                for scan in filtered_scans:
                    risk_dist[scan["risk_level"]] += 1
                for email in filtered_emails:
                    risk_dist[email["risk_level"]] += 1
                report_content += f"\nRisk Distribution:\n"
                for level, count in risk_dist.items():
                    report_content += f"- {level}: {count} files/emails\n"
                time.sleep(2)
                st.success("Report generated successfully!")
                st.download_button(
                    label="Download Report",
                    data=report_content,
                    file_name=f"dlp_report_{now.strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

    # User info and logout in sidebar
    st.sidebar.markdown("---")
    st.sidebar.info(f"Logged in as: {st.session_state.pending_user}")
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.verification_sent = False
        st.session_state.verification_code = None
        st.session_state.user_email = None
        st.session_state.pending_user = None
        st.session_state.auth_page = "login"
        st.rerun()

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
        <p>SecureDLP v1.0 | Data Protection and Compliance</p>
    </div>
    """,
    unsafe_allow_html=True
)