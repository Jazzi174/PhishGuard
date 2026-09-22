import streamlit as st
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
# ============================================================
# PHISHGUARD — ADVANCED THREAT INTELLIGENCE CENTER
# ============================================================
st.set_page_config(
    page_title="PhishGuard | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)
# ============================================================
# ADVANCED CYBERSECURITY UI
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}
.stApp {
    background:
        radial-gradient(circle at 15% 10%, rgba(0, 212, 255, 0.09), transparent 28%),
        radial-gradient(circle at 85% 15%, rgba(60, 100, 255, 0.08), transparent 25%),
        linear-gradient(180deg, #05080d 0%, #080d15 50%, #05080d 100%);
    color: #e6edf3;
}
.block-container {
    max-width: 1450px;
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}
/* ---------- HEADER ---------- */
.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0 18px 0;
    border-bottom: 1px solid rgba(148,163,184,0.12);
    margin-bottom: 25px;
}
.brand {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: 1.5px;
}
.brand-main {
    color: #ffffff;
}
.brand-accent {
    color: #00d9ff;
}
.status {
    color: #5eead4;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    background: rgba(20,184,166,0.08);
    border: 1px solid rgba(45,212,191,0.18);
    padding: 7px 12px;
    border-radius: 20px;
}
.subtitle {
    color: #718096;
    font-size: 12px;
    letter-spacing: 1.4px;
    margin-top: 5px;
}
/* ---------- HERO ---------- */
.hero {
    background:
        linear-gradient(135deg,
        rgba(8,18,30,0.96),
        rgba(7,14,24,0.92));
    border: 1px solid rgba(0,217,255,0.15);
    border-radius: 18px;
    padding: 34px;
    margin-bottom: 22px;
    position: relative;
    overflow: hidden;
}
.hero:after {
    content: "";
    position: absolute;
    width: 280px;
    height: 280px;
    right: -100px;
    top: -130px;
    border-radius: 50%;
    border: 1px solid rgba(0,217,255,0.10);
    box-shadow:
        0 0 0 30px rgba(0,217,255,0.02),
        0 0 0 60px rgba(0,217,255,0.015);
}
.hero-title {
    font-size: 34px;
    font-weight: 800;
    margin-bottom: 7px;
}
.hero-title span {
    color: #00d9ff;
}
.hero-description {
    color: #8492a6;
    font-size: 14px;
    max-width: 720px;
    line-height: 1.7;
}
/* ---------- SECTION TITLES ---------- */
.section-label {
    color: #00d9ff;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.8px;
    text-transform: uppercase;
    margin: 24px 0 10px 0;
}
/* ---------- CARDS ---------- */
.card {
    background: rgba(10,18,29,0.88);
    border: 1px solid rgba(148,163,184,0.10);
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 15px;
}
.card-title {
    color: #dce6f2;
    font-size: 13px;
    font-weight: 700;
    margin-bottom: 14px;
}
/* ---------- URL INPUT ---------- */
div[data-baseweb="input"] {
    background: #080f18 !important;
    border: 1px solid rgba(0,217,255,0.18) !important;
    border-radius: 10px !important;
}
div[data-baseweb="input"] input {
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
}
/* ---------- BUTTON ---------- */
div.stButton > button {
    width: 100%;
    min-height: 45px;
    border-radius: 9px;
    border: 1px solid rgba(0,217,255,0.25);
    background: linear-gradient(
        135deg,
        #009fc2,
        #007a9d
    );
    color: white;
    font-weight: 800;
    letter-spacing: 0.5px;
    transition: 0.2s;
}
div.stButton > button:hover {
    border-color: #00d9ff;
    background: linear-gradient(
        135deg,
        #00b8df,
        #008eb5
    );
}
/* ---------- METRIC CARDS ---------- */
.metric {
    background: rgba(9,17,28,0.94);
    border: 1px solid rgba(148,163,184,0.10);
    border-radius: 13px;
    padding: 18px;
    min-height: 105px;
}
.metric-label {
    color: #64748b;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.3px;
    text-transform: uppercase;
}
.metric-value {
    color: #f8fafc;
    font-size: 25px;
    font-weight: 800;
    margin-top: 9px;
}
.low {
    color: #34d399;
}
.medium {
    color: #fbbf24;
}
.high {
    color: #fb7185;
}
/* ---------- SCORE ---------- */
.score-box {
    text-align: center;
    background:
        radial-gradient(circle at center,
        rgba(0,217,255,0.08),
        transparent 60%),
        #08101a;
    border: 1px solid rgba(0,217,255,0.14);
    border-radius: 15px;
    padding: 25px;
}
.score-number {
    font-size: 58px;
    font-weight: 800;
    line-height: 1;
}
.score-caption {
    color: #64748b;
    font-size: 11px;
    letter-spacing: 1.4px;
    margin-top: 8px;
}
/* ---------- INDICATORS ---------- */
.indicator {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    margin-bottom: 8px;
    border-radius: 9px;
    background: rgba(15,23,36,0.75);
    border: 1px solid rgba(148,163,184,0.07);
}
.indicator-icon {
    font-size: 15px;
    width: 24px;
}
.indicator-title {
    color: #dbe5ef;
    font-size: 12px;
    font-weight: 700;
}
.indicator-description {
    color: #64748b;
    font-size: 11px;
    margin-top: 2px;
}
/* ---------- INTELLIGENCE ROWS ---------- */
.info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 0;
    border-bottom: 1px solid rgba(148,163,184,0.07);
}
.info-row:last-child {
    border-bottom: none;
}
.info-name {
    color: #718096;
    font-size: 11px;
}
.info-value {
    color: #dce6f2;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
}
/* ---------- BADGE ---------- */
.badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 6px;
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 0.8px;
}
/* ---------- FOOTER ---------- */
.footer {
    text-align: center;
    color: #475569;
    font-size: 10px;
    line-height: 1.8;
    margin-top: 40px;
    padding-top: 22px;
    border-top: 1px solid rgba(148,163,184,0.08);
}
/* ---------- HIDE STREAMLIT BRANDING ---------- */
#MainMenu {
    visibility: hidden;
}
footer {
    visibility: hidden;
}
header {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)
# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div class="topbar">
    <div>
        <div class="brand">
            <span class="brand-main">PHISH</span><span class="brand-accent">GUARD</span>
        </div>
        <div class="subtitle">
            THREAT INTELLIGENCE &nbsp;•&nbsp; URL RISK ANALYSIS
        </div>
    </div>
    <div class="status">
        ● SYSTEM ONLINE
    </div>
</div>
""", unsafe_allow_html=True)
# ============================================================
# HERO
# ============================================================
st.markdown("""
<div class="hero">
    <div class="hero-title">
        Analyze <span>URL Threats</span> Before You Click
    </div>
    <div class="hero-description">
        PhishGuard analyzes structural URL characteristics using a
        machine-learning model and security indicators to generate
        an estimated phishing risk score.
    </div>
</div>
""", unsafe_allow_html=True)
# ============================================================
# LOAD DATA
# ============================================================
@st.cache_data
def load_dataset():
    return pd.read_csv("phishguard_dataset.csv")
df = load_dataset()
# ============================================================
# MODEL
# ============================================================
FEATURES = [
    "url_length",
    "https",
    "has_ip",
    "dot_count",
    "hyphen_count",
    "at_count",
    "digit_count",
    "special_char_count",
    "suspicious_word_count",
    "subdomain_count",
    "shortener"
]
X = df[FEATURES]
y = df["label"]
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    random_state=42
)
model.fit(X, y)
# ============================================================
# FEATURE EXTRACTION
# ============================================================
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "signin",
        "confirm",
        "bank",
        "payment",
        "wallet"
    ]
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly"
    ]
    return {
        "url_length": len(url),
        "https": int(
            url.lower().startswith("https://")
        ),
        "has_ip": int(
            bool(
                re.search(
                    r"(?:\d{1,3}\.){3}\d{1,3}",
                    hostname
                )
            )
        ),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "digit_count": sum(
            c.isdigit() for c in url
        ),
        "special_char_count": sum(
            not c.isalnum() for c in url
        ),
        "suspicious_word_count": sum(
            word in url.lower()
            for word in suspicious_words
        ),
        "subdomain_count": max(
            len(hostname.split(".")) - 2,
            0
        ),
        "shortener": int(
            any(
                shortener in hostname
                for shortener in shorteners
            )
        )
    }
# ============================================================
# ANALYSIS
# ============================================================
def analyze_url(url):
    features = extract_features(url)
    feature_df = pd.DataFrame(
        [features],
        columns=FEATURES
    )
    prediction = model.predict(
        feature_df
    )[0]
    probabilities = model.predict_proba(
        feature_df
    )[0]
    suspicious_index = list(
        model.classes_
    ).index(1)
    probability = probabilities[
        suspicious_index
    ]
    risk_score = round(
        probability * 100
    )
    if risk_score < 30:
        risk_level = "LOW RISK"
        risk_class = "low"
    elif risk_score < 70:
        risk_level = "MEDIUM RISK"
        risk_class = "medium"
    else:
        risk_level = "HIGH RISK"
        risk_class = "high"
    return (
        features,
        prediction,
        probability,
        risk_score,
        risk_level,
        risk_class
    )
# ============================================================
# SECURITY INDICATORS
# ============================================================
def get_indicators(features):
    indicators = []
    if features["https"]:
        indicators.append(
            (
                "✓",
                "Secure Protocol",
                "HTTPS detected"
            )
        )
    else:
        indicators.append(
            (
                "⚠",
                "Secure Protocol",
                "HTTPS not detected"
            )
        )
    if features["has_ip"]:
        indicators.append(
            (
                "⚠",
                "IP Address",
                "Direct IP address detected"
            )
        )
    else:
        indicators.append(
            (
                "✓",
                "IP Address",
                "No direct IP detected"
            )
        )
    if features["suspicious_word_count"]:
        indicators.append(
            (
                "⚠",
                "Suspicious Keywords",
                f"{features['suspicious_word_count']} detected"
            )
        )
    else:
        indicators.append(
            (
                "✓",
                "Suspicious Keywords",
                "None detected"
            )
        )
    if features["url_length"] > 75:
        indicators.append(
            (
                "⚠",
                "URL Length",
                "Unusually long URL"
            )
        )
    else:
        indicators.append(
            (
                "✓",
                "URL Length",
                "Within normal range"
            )
        )
    if features["hyphen_count"] >= 3:
        indicators.append(
            (
                "⚠",
                "Hyphen Pattern",
                "Multiple hyphens detected"
            )
        )
    else:
        indicators.append(
            (
                "✓",
                "Hyphen Pattern",
                "No unusual pattern"
            )
        )
    if features["at_count"]:
        indicators.append(
            (
                "⚠",
                "@ Symbol",
                "@ character detected"
            )
        )
    else:
        indicators.append(
            (
                "✓",
                "@ Symbol",
                "Not detected"
            )
        )
    return indicators
# ============================================================
# ANALYZER INPUT
# ============================================================
st.markdown(
    '<div class="section-label">TARGET ANALYSIS</div>',
    unsafe_allow_html=True
)
url = st.text_input(
    "Target URL",
    placeholder="https://example.com/login",
    label_visibility="collapsed"
)
analyze = st.button(
    "🔍  ANALYZE THREAT"
)
# ============================================================
# RESULTS
# ============================================================
if analyze:
    if not url.strip():
        st.warning(
            "Enter a URL to begin the threat analysis."
        )
    else:
        try:
            (
                features,
                prediction,
                probability,
                risk_score,
                risk_level,
                risk_class
            ) = analyze_url(url)
            indicators = get_indicators(
                features
            )
            # ------------------------------------------------
            # TARGET
            # ------------------------------------------------
            st.markdown(
                f"""
                <div class="card">
                    <div class="section-label">
                        ANALYZED TARGET
                    </div>
                    <div style="
                        font-family:'JetBrains Mono';
                        font-size:13px;
                        color:#cbd5e1;
                        word-break:break-all;
                    ">
                        {url}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            # ------------------------------------------------
            # TOP METRICS
            # ------------------------------------------------
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(
                    f"""
                    <div class="metric">
                        <div class="metric-label">
                            Threat Score
                        </div>
                        <div class="metric-value {risk_class}">
                            {risk_score}/100
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c2:
                st.markdown(
                    f"""
                    <div class="metric">
                        <div class="metric-label">
                            Risk Level
                        </div>
                        <div class="metric-value {risk_class}">
                            {risk_level}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c3:
                classification = (
                    "SUSPICIOUS"
                    if prediction == 1
                    else "LOW CONCERN"
                )
                st.markdown(
                    f"""
                    <div class="metric">
                        <div class="metric-label">
                            Classification
                        </div>
                        <div class="metric-value">
                            {classification}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with c4:
                st.markdown(
                    f"""
                    <div class="metric">
                        <div class="metric-label">
                            Model Probability
                        </div>
                        <div class="metric-value">
                            {probability * 100:.1f}%
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.write("")
            # ------------------------------------------------
            # SCORE + INTELLIGENCE
            # ------------------------------------------------
            left, right = st.columns(
                [0.9, 1.5]
            )
            with left:
                st.markdown(
                    '<div class="section-label">RISK ASSESSMENT</div>',
                    unsafe_allow_html=True
                )
                st.markdown(
                    f"""
                    <div class="score-box">
                        <div class="score-number {risk_class}">
                            {risk_score}
                        </div>
                        <div class="score-caption">
                            ESTIMATED THREAT SCORE / 100
                        </div>
                        <div style="
                            margin-top:18px;
                            color:#94a3b8;
                            font-size:11px;
                            line-height:1.6;
                        ">
                            Based on URL structural characteristics
                            and Random Forest model probability.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            with right:
                st.markdown(
                    '<div class="section-label">URL INTELLIGENCE</div>',
                    unsafe_allow_html=True
                )
                st.markdown(
                    '<div class="card">',
                    unsafe_allow_html=True
                )
                parsed = urlparse(url)
                domain = (
                    parsed.netloc
                    if parsed.netloc
                    else "Not detected"
                )
                protocol = (
                    parsed.scheme.upper()
                    if parsed.scheme
                    else "Unknown"
                )
                intelligence = [
                    (
                        "DOMAIN",
                        domain
                    ),
                    (
                        "PROTOCOL",
                        protocol
                    ),
                    (
                        "URL LENGTH",
                        str(features["url_length"])
                    ),
                    (
                        "SUBDOMAINS",
                        str(features["subdomain_count"])
                    ),
                    (
                        "DOT COUNT",
                        str(features["dot_count"])
                    ),
                    (
                        "DIGITS",
                        str(features["digit_count"])
                    ),
                    (
                        "SPECIAL CHARACTERS",
                        str(features["special_char_count"])
                    )
                ]
                for name, value in intelligence:
                    st.markdown(
                        f"""
                        <div class="info-row">
                            <span class="info-name">
                                {name}
                            </span>
                            <span class="info-value">
                                {value}
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                st.markdown(
                    '</div>',
                    unsafe_allow_html=True
                )
            # ------------------------------------------------
            # SECURITY INDICATORS
            # ------------------------------------------------
            st.markdown(
                '<div class="section-label">SECURITY INDICATORS</div>',
                unsafe_allow_html=True
            )
            ind_left, ind_right = st.columns(2)
            for index, item in enumerate(indicators):
                icon, title, description = item
                target_column = (
                    ind_left
                    if index % 2 == 0
                    else ind_right
                )
                with target_column:
                    icon_class = (
                        "low"
                        if icon == "✓"
                        else "medium"
                    )
                    st.markdown(
                        f"""
                        <div class="indicator">
                            <div class="indicator-icon {icon_class}">
                                {icon}
                            </div>
                            <div>
                                <div class="indicator-title">
                                    {title}
                                </div>
                                <div class="indicator-description">
                                    {description}
                                </div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            # ------------------------------------------------
            # MACHINE LEARNING PANEL
            # ------------------------------------------------
            st.markdown(
                '<div class="section-label">MACHINE LEARNING ANALYSIS</div>',
                unsafe_allow_html=True
            )
            st.markdown(
                f"""
                <div class="card">
                    <div class="card-title">
                        Random Forest Classification
                    </div>
                    <div style="
                        color:#8492a6;
                        font-size:12px;
                        line-height:1.7;
                    ">
                        PhishGuard analyzes the URL using
                        <strong style="color:#dbeafe;">
                        {len(FEATURES)} engineered URL features
                        </strong>
                        and a Random Forest classification model.
                        The model produced an estimated suspicious
                        probability of
                        <strong style="color:#00d9ff;">
                        {probability * 100:.1f}%
                        </strong>.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            # ------------------------------------------------
            # FEATURE SNAPSHOT
            # ------------------------------------------------
            st.markdown(
                '<div class="section-label">FEATURE SNAPSHOT</div>',
                unsafe_allow_html=True
            )
            feature_cols = st.columns(4)
            snapshot = [
                (
                    "HTTPS",
                    "YES" if features["https"] else "NO"
                ),
                (
                    "IP DETECTED",
                    "YES" if features["has_ip"] else "NO"
                ),
                (
                    "SHORTENER",
                    "YES" if features["shortener"] else "NO"
                ),
                (
                    "SUSPICIOUS WORDS",
                    str(features["suspicious_word_count"])
                )
            ]
            for column, (name, value) in zip(
                feature_cols,
                snapshot
            ):
                with column:
                    st.markdown(
                        f"""
                        <div class="metric">
                            <div class="metric-label">
                                {name}
                            </div>
                            <div class="metric-value"
                                 style="font-size:19px;">
                                {value}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
        except Exception as error:
            st.error(
                f"Analysis error: {error}"
            )
# ============================================================
# DISCLAIMER + FOOTER
# ============================================================
st.markdown(
    """
    <div class="footer">
        <strong>PHISHGUARD</strong>
        &nbsp;•&nbsp;
        MACHINE-LEARNING-BASED URL RISK ANALYSIS
        <br>
        Educational cybersecurity prototype.
        The model was trained using a synthetic dataset and
        should not be treated as definitive evidence that a URL
        is safe or malicious.
    </div>
    """,
    unsafe_allow_html=True
)
