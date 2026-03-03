import streamlit as st
import pandas as pd
import os
import pickle
from datetime import datetime
import plotly.graph_objects as go

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="InternshipDetector",
    page_icon="🛡",
    layout="wide"
)

# =====================================================
# BASIC STYLING
# =====================================================
st.markdown("""
<style>
.main {background-color: #0E1117;}
.block-container {padding-top: 2rem;}
.stButton>button {
    background-color: #4CAF50;
    color: white;
    border-radius: 8px;
    height: 3em;
    width: 100%;
}
</style>
""", unsafe_allow_html=True)

# =====================================================
# PATH SETUP
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
MODEL_DIR = os.path.join(BASE_DIR, "..", "model")

USERS_FILE = os.path.join(DATA_DIR, "users.csv")
BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklisted_domains.csv")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.csv")

MODEL_FILE = os.path.join(MODEL_DIR, "scam_model.pkl")
VECTORIZER_FILE = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")

# =====================================================
# LOAD MODEL
# =====================================================
with open(MODEL_FILE, "rb") as f:
    model = pickle.load(f)

with open(VECTORIZER_FILE, "rb") as f:
    vectorizer = pickle.load(f)

# =====================================================
# SESSION STATE
# =====================================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None

# =====================================================
# AUTH FUNCTIONS
# =====================================================
def register_user(username, password):
    users = pd.read_csv(USERS_FILE)
    if username in users["username"].values:
        return False
    new_user = pd.DataFrame([[username, password]], columns=["username", "password"])
    users = pd.concat([users, new_user], ignore_index=True)
    users.to_csv(USERS_FILE, index=False)
    return True


def login_user(username, password):
    users = pd.read_csv(USERS_FILE)
    user = users[(users["username"] == username) &
                 (users["password"] == password)]
    return not user.empty


def logout():
    st.session_state.logged_in = False
    st.session_state.username = None

# =====================================================
# ADMIN DASHBOARD
# =====================================================
def admin_dashboard():
    st.title("🛠 Admin Dashboard")
    st.subheader("Registered Users")
    st.dataframe(pd.read_csv(USERS_FILE))

    if os.path.exists(AUDIT_FILE):
        st.subheader("Audit Logs")
        st.dataframe(pd.read_csv(AUDIT_FILE))

# =====================================================
# USER DASHBOARD
# =====================================================
def user_dashboard():

    st.markdown("""
    <h1 style='text-align:center;'>🛡 InternshipDetector</h1>
    <p style='text-align:center;color:gray;'>
    AI-Powered Internship Scam Detection Platform
    </p>
    """, unsafe_allow_html=True)

    menu = st.sidebar.selectbox(
        "Navigation",
        ["Verify Internship", "History", "Logout"]
    )

    # =====================================================
    # VERIFY INTERNSHIP
    # =====================================================
    if menu == "Verify Internship":

        st.markdown("## 🔍 Internship Verification")

        col1, col2 = st.columns(2)

        with col1:
            company_name = st.text_input("🏢 Company Name")
            official_email = st.text_input("📧 Official Email ID")

        with col2:
            website = st.text_input("🌐 Official Website")

        description = st.text_area("📝 Internship Description", height=150)
        enquiry = st.text_area("⚠ Additional Concerns (Optional)", height=100)

        if official_email and "@" not in official_email:
            st.warning("⚠ Invalid email format detected.")

        analyze = st.button("Analyze Internship")

        if analyze:

            with st.spinner("🔎 Running AI Risk Analysis..."):

                risk_score = 0
                reasons = []

                # Missing info
                if not company_name:
                    risk_score += 10
                    reasons.append("Company name not provided.")

                if not website:
                    risk_score += 15
                    reasons.append("No official website provided.")

                # Email domain match
                if official_email and website:
                    try:
                        email_domain = official_email.split("@")[1].lower()
                        website_domain = website.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].lower()
                        if email_domain not in website_domain:
                            risk_score += 25
                            reasons.append("Email domain does not match website.")
                    except:
                        pass

                # Free email penalty
                free_emails = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
                if official_email and any(f in official_email.lower() for f in free_emails):
                    risk_score += 20
                    reasons.append("Using free email provider.")

                # Suspicious extensions
                suspicious_extensions = [".xyz", ".top", ".buzz", ".click", ".online"]
                if website and any(ext in website.lower() for ext in suspicious_extensions):
                    risk_score += 20
                    reasons.append("Suspicious domain extension detected.")

                # Blacklist
                blacklist = pd.read_csv(BLACKLIST_FILE)
                if website:
                    for domain in blacklist.iloc[:, 0].values:
                        if domain.lower() in website.lower():
                            risk_score += 40
                            reasons.append("Website is blacklisted.")

                # Financial keywords
                financial_keywords = {
                    "registration fee": 30,
                    "pay": 20,
                    "payment": 20,
                    "fees": 20,
                    "money transfer": 30,
                    "upi": 25,
                    "urgent": 10
                }

                combined_text = (description + " " + enquiry).lower()
                for word, weight in financial_keywords.items():
                    if word in combined_text:
                        risk_score += weight
                        reasons.append(f"Financial keyword detected: {word}")

                # ML prediction
                if description:
                    vector = vectorizer.transform([description])
                    prediction = model.predict(vector)[0]
                    if prediction == 1:
                        risk_score += 30
                        reasons.append("AI model flagged as scam.")

                if risk_score > 100:
                    risk_score = 100

            # ===============================
            # RISK LEVEL BANNER
            # ===============================
            if risk_score >= 60:
                st.error("🚨 HIGH RISK INTERNSHIP")
            elif risk_score >= 30:
                st.warning("⚠ MEDIUM RISK - Proceed Carefully")
            else:
                st.success("✅ LOW RISK - Appears Safe")

            # ===============================
            # GAUGE
            # ===============================
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                title={'text': "Risk Score"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "red" if risk_score >= 60 else "orange" if risk_score >= 30 else "green"},
                }
            ))
            st.plotly_chart(fig, use_container_width=True)

            # ===============================
            # PIE CHART BREAKDOWN
            # ===============================
            breakdown = go.Figure(data=[go.Pie(
                labels=["Total Risk", "Safe Portion"],
                values=[risk_score, 100-risk_score],
                hole=.4
            )])
            breakdown.update_layout(title="Risk Distribution")
            st.plotly_chart(breakdown, use_container_width=True)

            # ===============================
            # REASONS
            # ===============================
            if reasons:
                with st.expander("🧠 View Detailed AI Reasoning"):
                    for r in reasons:
                        st.write("•", r)

            # Save audit log
            log_data = pd.DataFrame([[
                st.session_state.username,
                company_name,
                official_email,
                website,
                risk_score,
                datetime.now()
            ]], columns=[
                "username",
                "company_name",
                "email",
                "website",
                "risk_score",
                "timestamp"
            ])

            if os.path.exists(AUDIT_FILE):
                log_data.to_csv(AUDIT_FILE, mode="a", header=False, index=False)
            else:
                log_data.to_csv(AUDIT_FILE, index=False)

    # =====================================================
    # HISTORY
    # =====================================================
    elif menu == "History":
        if os.path.exists(AUDIT_FILE):
            logs = pd.read_csv(AUDIT_FILE)
            user_logs = logs[logs["username"] == st.session_state.username]
            st.dataframe(user_logs)

    elif menu == "Logout":
        logout()
        st.rerun()

# =====================================================
# MAIN
# =====================================================
if not st.session_state.logged_in:

    st.title("InternshipDetector")

    choice = st.sidebar.selectbox(
        "Choose Option",
        ["Login", "Register"]
    )

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Register":
        if st.button("Register"):
            if register_user(username, password):
                st.success("Registered Successfully")
            else:
                st.error("Username already exists")

    elif choice == "Login":
        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid Credentials")

else:
    if st.session_state.username == "admin":
        admin_dashboard()
    else:
        user_dashboard()