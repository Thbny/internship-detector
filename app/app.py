import streamlit as st
import pandas as pd
import os
from datetime import datetime
import re

# ==============================
# PATH SETUP
# ==============================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")

USERS_FILE = os.path.join(DATA_DIR, "users.csv")
VERIFIED_FILE = os.path.join(DATA_DIR, "verified_companies.csv")
BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklisted_domains.csv")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.csv")

# ==============================
# SESSION INIT
# ==============================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None

# ==============================
# AUTH FUNCTIONS
# ==============================

def register_user(username, password):
    users_db = pd.read_csv(USERS_FILE)
    if username in users_db["username"].values:
        return False
    new_user = pd.DataFrame([[username, password]], columns=["username", "password"])
    new_user.to_csv(USERS_FILE, mode="a", header=False, index=False)
    return True

def login_user(username, password):
    users_db = pd.read_csv(USERS_FILE)

    users_db["username"] = users_db["username"].astype(str).str.strip()
    users_db["password"] = users_db["password"].astype(str).str.strip()

    username = username.strip()
    password = password.strip()

    if username in users_db["username"].values:
        stored_password = users_db.loc[
            users_db["username"] == username, "password"
        ].values[0]
        return stored_password == password

    return False

# ==============================
# RISK DETECTOR
# ==============================

def calculate_risk(company_name, website, email, payment_required, description):
    risk = 0

    # Payment rule
    if payment_required == "Yes":
        risk += 30

    # Free email rule
    if any(x in email.lower() for x in ["gmail.com", "yahoo.com", "outlook.com"]):
        risk += 20

    # Government verification
    verified_db = pd.read_csv(VERIFIED_FILE)
    if company_name not in verified_db["company_name"].values:
        risk += 25

    # Blacklist domain check
    blacklist_db = pd.read_csv(BLACKLIST_FILE)
    domain = website.replace("https://", "").replace("http://", "").split("/")[0]
    if domain in blacklist_db["domain"].values:
        risk += 40

    # Suspicious keywords
    suspicious_words = [
        "urgent", "limited seats", "registration fee",
        "pay now", "guaranteed job", "instant offer letter"
    ]

    for word in suspicious_words:
        if word in description.lower():
            risk += 10

    return min(risk, 100)

# ==============================
# UI
# ==============================

st.title("InternshipDetector")
st.caption("AI-Powered Scam Internship Detection Platform")

if not st.session_state.logged_in:

    option = st.sidebar.selectbox("Choose Option", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if option == "Register":
        if st.button("Register"):
            if register_user(username, password):
                st.success("Registration successful. Please login.")
            else:
                st.warning("Username already exists.")

    if option == "Login":
        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid credentials")

else:
    st.success(f"Welcome, {st.session_state.username}")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    st.header("Scam Internship Detector")

    company_name = st.text_input("Company Name")
    website = st.text_input("Official Website")
    email = st.text_input("Official Email")
    payment_required = st.selectbox("Is payment required?", ["No", "Yes"])
    description = st.text_area("Internship Description")

    if st.button("Verify Internship"):

        risk_score = calculate_risk(
            company_name, website, email, payment_required, description
        )

        # Risk Display
        if risk_score >= 75:
            st.error("🔴 HIGH RISK - Likely Fake Internship")
        elif risk_score >= 40:
            st.warning("🟠 MEDIUM RISK - Suspicious")
        else:
            st.success("🟢 LOW RISK - Likely Genuine")

        st.progress(risk_score)
        st.metric("Risk Score", f"{risk_score}/100")

        # Government verification display
        verified_db = pd.read_csv(VERIFIED_FILE)
        if company_name in verified_db["company_name"].values:
            st.success("Company found in Government Records")
        else:
            st.warning("Company NOT found in Government Records")

        # Audit logging
        log_entry = pd.DataFrame([{
            "timestamp": datetime.now(),
            "user": st.session_state.username,
            "company_name": company_name,
            "risk_score": risk_score
        }])

        log_entry.to_csv(AUDIT_FILE, mode="a", header=False, index=False)