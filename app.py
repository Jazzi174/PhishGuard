import streamlit as st
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="PhishGuard | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 15% 10%, rgba(0, 220, 255, 0.08), transparent 28%),
        radial-gradient(circle at 85% 20%, rgba(50, 90, 255, 0.08), transparent 30%),
        #050a12;
    color: #e8f1ff;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}

h1, h2, h3 {
    letter-spacing: -0.5px;
}

.brand {
    font-size: 1.05rem;
    font-weight: 800;
    letter-spacing: 3px;
    color: #58e6ff;
}

.system-online {
    display: inline-block;
    padding: 5px 11px;
    border-radius: 20px;
    background: rgba(0, 255, 170, 0.08);
    border: 1px solid rgba(0, 255, 170, 0.25);
    color: #50f0b0;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 1px;
}

.hero-title {
    font-size: 3.1rem;
    line-height: 1.05;
    font-weight: 800;
    margin-top: 25px;
    margin-bottom: 12px;
}

.hero-subtitle {
    color: #8ea2bd;
    font-size: 1rem;
    max-width: 760px;
    line-height: 1.7;
}

.section-title {
    margin-top: 32px;
    margin-bottom: 15px;
    font-size: 1.15rem;
    font-weight: 800;
    color: #dcecff;
}

.metric-card {
    background: linear-gradient(145deg, rgba(17,29,46,0.95), rgba(8,17,29,0.95));
    border: 1px solid rgba(85, 130, 180, 0.18);
    border-radius: 16px;
    padding: 20px;
    min-height: 125px;
    box-shadow: 0 8px 30px rgba(0,0,0,0.18);
}

.metric-label {
    color: #8095b0;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    font-weight: 700;
}

.metric-value {
    color: #eef7ff;
    font-size: 1.65rem;
    font-weight: 800;
    margin-top: 8px;
}

.panel {
    background: rgba(9, 18, 30, 0.88);
    border: 1px solid rgba(90, 135, 185, 0.18);
    border-radius: 18px;
    padding: 22px;
    margin-top: 14px;
}

.intel-item {
    background: rgba(18, 31, 48, 0.72);
    border: 1px solid rgba(90, 135, 185, 0.12);
    border-radius: 12px;
    padding: 13px;
    margin-bottom: 9px;
}

.intel-label {
    color: #7187a3;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.intel-value {
    color: #dcecff;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.88rem;
    margin-top: 4px;
}

.good {
    color: #55e6a5;
    font-weight: 700;
}

.warning {
    color: #ffd166;
    font-weight: 700;
}

.danger {
    color: #ff667d;
    font-weight: 700;
}

.info {
    color: #58d9ff;
    font-weight: 700;
}

.explanation {
    background: rgba(12, 25, 41, 0.8);
    border-left: 3px solid #58d9ff;
    padding: 14px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
    color: #b9c9dc;
    line-height: 1.55;
}

.footer {
    margin-top: 45px;
    padding-top: 20px;
    border-top: 1px solid rgba(90, 135, 185, 0.15);
    color: #60748d;
    font-size: 0.75rem;
    line-height: 1.6;
}

div.stButton > button {
    width: 100%;
    border-radius: 10px;
    border: 1px solid rgba(88, 230, 255, 0.3);
    background: linear-gradient(135deg, #0d536b, #123c67);
    color: white;
    font-weight: 800;
    padding: 0.65rem;
}

div.stButton > button:hover {
    border-color: #58e6ff;
    color: #ffffff;
}

[data-testid="stMetric"] {
    background: rgba(12, 24, 39, 0.85);
    border: 1px solid rgba(90, 135, 185, 0.16);
    padding: 15px;
    border-radius: 14px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# LOAD DATA
# =========================================================

@st.cache_data
def load_data():
    return pd.read_csv("phishguard_dataset.csv")


df = load_data()


# =========================================================
# FEATURES
# =========================================================

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

TARGET = "label"


# =========================================================
# FEATURE EXTRACTION
# =========================================================

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "bank",
    "password",
    "signin",
    "wallet",
    "security",
    "recover",
    "unlock"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly"
]


def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.netloc.lower()

    if not hostname:
        hostname = parsed.path.split("/")[0].lower()

    url_lower = url.lower()

    digits = len(re.findall(r"\d", url))
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", url))

    suspicious_count = sum(
        1 for word in SUSPICIOUS_WORDS
        if word in url_lower
    )

    subdomain_count = max(0, hostname.count(".") - 1)

    is_shortener = int(
        any(shortener in hostname for shortener in SHORTENERS)
    )

    has_ip = int(
        bool(
            re.search(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                hostname
            )
        )
    )

    return {
        "url_length": len(url),
        "https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "digit_count": digits,
        "special_char_count": special_chars,
        "suspicious_word_count": suspicious_count,
        "subdomain_count": subdomain_count,
        "shortener": is_shortener
    }


# =========================================================
# MODEL TRAINING
# =========================================================

X = df[FEATURES]
y = df[TARGET]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


@st.cache_resource
def train_models(X_train, X_test, y_train, y_test):

    models = {

        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000))
        ]),

        "Decision Tree": DecisionTreeClassifier(
            max_depth=8,
            random_state=42
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            random_state=42
        )
    }

    results = {}
    trained_models = {}

    for name, model in models.items():

        model.fit(X_train, y_train)

        predictions = model.predict(X_test)

        results[name] = {
            "accuracy": accuracy_score(y_test, predictions),
            "precision": precision_score(
                y_test,
                predictions,
                zero_division=0
            ),
            "recall": recall_score(
                y_test,
                predictions,
                zero_division=0
            ),
            "f1": f1_score(
                y_test,
                predictions,
                zero_division=0
            ),
            "confusion_matrix": confusion_matrix(
                y_test,
                predictions
            )
        }

        trained_models[name] = model

    return trained_models, results


models, results = train_models(
    X_train,
    X_test,
    y_train,
    y_test
)


model = models["Random Forest"]


# =========================================================
# SESSION HISTORY
# =========================================================

if "history" not in st.session_state:
    st.session_state.history = []


# =========================================================
# HEADER
# =========================================================

header_left, header_right = st.columns([7, 2])

with header_left:
    st.markdown(
        '<div class="brand">PHISHGUARD</div>',
        unsafe_allow_html=True
    )

with header_right:
    st.markdown(
        '<div style="text-align:right;">'
        '<span class="system-online">● SYSTEM ONLINE</span>'
        '</div>',
        unsafe_allow_html=True
    )


st.markdown(
    '<div class="hero-title">'
    'Analyze URL Threats Before You Click'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="hero-subtitle">'
    'PhishGuard uses machine learning and URL-based threat indicators '
    'to estimate phishing risk and explain the signals behind each assessment.'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# URL ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">THREAT ANALYSIS</div>',
    unsafe_allow_html=True
)

url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com/login",
    label_visibility="collapsed"
)

analyze = st.button(
    "⚡ ANALYZE THREAT"
)


if analyze:

    if not url.strip():

        st.warning("Please enter a URL before starting the analysis.")

    else:

        features = extract_features(url)

        feature_df = pd.DataFrame(
            [features],
            columns=FEATURES
        )

        probability = model.predict_proba(feature_df)[0][1]

        risk_score = round(float(probability * 100), 2)

        if risk_score < 30:
            risk_level = "LOW RISK"
            classification = "LIKELY SAFE"
            risk_class = "good"

        elif risk_score < 70:
            risk_level = "MEDIUM RISK"
            classification = "SUSPICIOUS"
            risk_class = "warning"

        else:
            risk_level = "HIGH RISK"
            classification = "POTENTIAL PHISHING"
            risk_class = "danger"


        # ---------------------------------------------
        # SAVE HISTORY
        # ---------------------------------------------

        st.session_state.history.insert(
            0,
            {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "URL": url,
                "Risk Score": risk_score,
                "Risk Level": risk_level,
                "Classification": classification
            }
        )

        st.session_state.history = (
            st.session_state.history[:10]
        )


        # ---------------------------------------------
        # TOP METRICS
        # ---------------------------------------------

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">Threat Score</div>
                    <div class="metric-value">{risk_score}/100</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c2:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">Risk Level</div>
                    <div class="metric-value {risk_class}">
                        {risk_level}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c3:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">Classification</div>
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
                <div class="metric-card">
                    <div class="metric-label">Model Probability</div>
                    <div class="metric-value">
                        {probability * 100:.1f}%
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


        # ---------------------------------------------
        # RISK ASSESSMENT
        # ---------------------------------------------

        st.markdown(
            '<div class="section-title">RISK ASSESSMENT</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            f"""
            <div class="panel">
                <div style="font-size:1.2rem;font-weight:800;"
                     class="{risk_class}">
                    {classification}
                </div>

                <div style="color:#8ea2bd;margin-top:8px;">
                    Estimated phishing risk based on URL structure,
                    lexical indicators and machine-learning analysis.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


        # ---------------------------------------------
        # URL INTELLIGENCE
        # ---------------------------------------------

        st.markdown(
            '<div class="section-title">URL INTELLIGENCE</div>',
            unsafe_allow_html=True
        )

        parsed = urlparse(url)

        domain = parsed.netloc

        if not domain:
            domain = parsed.path.split("/")[0]

        i1, i2, i3 = st.columns(3)

        with i1:
            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Domain</div>
                    <div class="intel-value">{domain}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">URL Length</div>
                    <div class="intel-value">
                        {features["url_length"]} characters
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Subdomains</div>
                    <div class="intel-value">
                        {features["subdomain_count"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with i2:
            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Protocol</div>
                    <div class="intel-value">
                        {parsed.scheme.upper() or "UNKNOWN"}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Dot Count</div>
                    <div class="intel-value">
                        {features["dot_count"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Digits</div>
                    <div class="intel-value">
                        {features["digit_count"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with i3:
            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Special Characters</div>
                    <div class="intel-value">
                        {features["special_char_count"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">Suspicious Words</div>
                    <div class="intel-value">
                        {features["suspicious_word_count"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                f"""
                <div class="intel-item">
                    <div class="intel-label">IP Address</div>
                    <div class="intel-value">
                        {"Detected" if features["has_ip"] else "Not detected"}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


        # ---------------------------------------------
        # SECURITY INDICATORS
        # ---------------------------------------------

        st.markdown(
            '<div class="section-title">SECURITY INDICATORS</div>',
            unsafe_allow_html=True
        )

        s1, s2, s3, s4 = st.columns(4)

        with s1:
            protocol_status = (
                "Secure"
                if features["https"]
                else "Not Secure"
            )

            st.metric(
                "HTTPS",
                protocol_status
            )

        with s2:
            st.metric(
                "IP Address",
                "Detected" if features["has_ip"] else "None"
            )

        with s3:
            st.metric(
                "Suspicious Keywords",
                features["suspicious_word_count"]
            )

        with s4:
            st.metric(
                "Shortener",
                "Detected" if features["shortener"] else "None"
            )


        # ---------------------------------------------
        # EXPLAINABLE AI
        # ---------------------------------------------

        st.markdown(
            '<div class="section-title">EXPLAINABLE AI — WHY THIS SCORE?</div>',
            unsafe_allow_html=True
        )

        explanations = []

        if features["https"] == 0:
            explanations.append(
                "The URL does not use HTTPS. Lack of encrypted transport "
                "is a security warning, although HTTPS alone does not prove "
                "that a website is legitimate."
            )

        if features["has_ip"]:
            explanations.append(
                "The hostname contains an IP address instead of a conventional "
                "domain name, which can be a suspicious URL characteristic."
            )

        if features["suspicious_word_count"] > 0:
            explanations.append(
                f"The URL contains {features['suspicious_word_count']} "
                "security-related or account-related keyword(s), such as "
                "login, verify, secure, account or password."
            )

        if features["at_count"] > 0:
            explanations.append(
                "The URL contains an '@' symbol, a structure sometimes used "
                "to obscure the actual destination."
            )

        if features["shortener"]:
            explanations.append(
                "A URL-shortening service was detected, which hides the "
                "destination URL and reduces transparency."
            )

        if features["subdomain_count"] >= 3:
            explanations.append(
                "The URL contains several subdomain levels, increasing "
                "structural complexity."
            )

        if features["url_length"] > 100:
            explanations.append(
                "The URL is relatively long, which can be associated with "
                "complex or deceptive URL structures."
            )

        if features["hyphen_count"] >= 3:
            explanations.append(
                "The URL contains several hyphens, which may contribute "
                "to a suspicious lexical pattern."
            )

        if not explanations:
            explanations.append(
                "No major URL-level warning indicators were detected. "
                "This does not guarantee that the destination is safe."
            )

        for explanation in explanations:

            st.markdown(
                f"""
                <div class="explanation">
                    {explanation}
                </div>
                """,
                unsafe_allow_html=True
            )


        # ---------------------------------------------
        # MACHINE LEARNING ANALYSIS
        # ---------------------------------------------

        st.markdown(
            '<div class="section-title">MACHINE LEARNING ANALYSIS</div>',
            unsafe_allow_html=True
        )

        m1, m2 = st.columns(2)

        with m1:

            st.markdown(
                """
                <div class="panel">
                    <h3>Feature Snapshot</h3>
                """,
                unsafe_allow_html=True
            )

            snapshot = pd.DataFrame({
                "Feature": [
                    "HTTPS",
                    "IP Detected",
                    "Shortener",
                    "Suspicious Words",
                    "Subdomains",
                    "URL Length"
                ],
                "Value": [
                    features["https"],
                    features["has_ip"],
                    features["shortener"],
                    features["suspicious_word_count"],
                    features["subdomain_count"],
                    features["url_length"]
                ]
            })

            st.dataframe(
                snapshot,
                use_container_width=True,
                hide_index=True
            )

            st.markdown("</div>", unsafe_allow_html=True)


        with m2:

            st.markdown(
                """
                <div class="panel">
                    <h3>Random Forest Feature Importance</h3>
                """,
                unsafe_allow_html=True
            )

            importance = pd.DataFrame({
                "Feature": FEATURES,
                "Importance": model.feature_importances_
            }).sort_values(
                "Importance",
                ascending=False
            )

            st.bar_chart(
                importance.set_index("Feature")
            )

            st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# DASHBOARD
# =========================================================

st.markdown(
    '<div class="section-title">MODEL PERFORMANCE</div>',
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# PERFORMANCE CARDS
# ---------------------------------------------------------

rf_results = results["Random Forest"]

p1, p2, p3, p4 = st.columns(4)

with p1:
    st.metric(
        "Accuracy",
        f"{rf_results['accuracy'] * 100:.1f}%"
    )

with p2:
    st.metric(
        "Precision",
        f"{rf_results['precision'] * 100:.1f}%"
    )

with p3:
    st.metric(
        "Recall",
        f"{rf_results['recall'] * 100:.1f}%"
    )

with p4:
    st.metric(
        "F1 Score",
        f"{rf_results['f1'] * 100:.1f}%"
    )


# ---------------------------------------------------------
# MODEL COMPARISON
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">MODEL COMPARISON</div>',
    unsafe_allow_html=True
)

comparison = pd.DataFrame({

    "Model": list(results.keys()),

    "Accuracy": [
        results[m]["accuracy"]
        for m in results
    ],

    "Precision": [
        results[m]["precision"]
        for m in results
    ],

    "Recall": [
        results[m]["recall"]
        for m in results
    ],

    "F1 Score": [
        results[m]["f1"]
        for m in results
    ]
})

display_comparison = comparison.copy()

for column in [
    "Accuracy",
    "Precision",
    "Recall",
    "F1 Score"
]:
    display_comparison[column] = (
        display_comparison[column] * 100
    ).round(2).astype(str) + "%"


st.dataframe(
    display_comparison,
    use_container_width=True,
    hide_index=True
)


# ---------------------------------------------------------
# FEATURE IMPORTANCE
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">FEATURE IMPORTANCE</div>',
    unsafe_allow_html=True
)

feature_importance = pd.DataFrame({

    "Feature": FEATURES,

    "Importance": model.feature_importances_

}).sort_values(
    "Importance",
    ascending=False
)

fi_left, fi_right = st.columns([1, 1])

with fi_left:

    st.dataframe(
        feature_importance,
        use_container_width=True,
        hide_index=True
    )

with fi_right:

    st.bar_chart(
        feature_importance.set_index("Feature")
    )


# ---------------------------------------------------------
# CONFUSION MATRIX
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">RANDOM FOREST CONFUSION MATRIX</div>',
    unsafe_allow_html=True
)

cm = rf_results["confusion_matrix"]

cm_df = pd.DataFrame(
    cm,
    index=["Actual Safe", "Actual Phishing"],
    columns=["Predicted Safe", "Predicted Phishing"]
)

st.dataframe(
    cm_df,
    use_container_width=True
)


# ---------------------------------------------------------
# ANALYSIS HISTORY
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">SESSION ANALYSIS HISTORY</div>',
    unsafe_allow_html=True
)

if st.session_state.history:

    history_df = pd.DataFrame(
        st.session_state.history
    )

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No URLs analyzed in this session yet. "
        "Run a URL analysis above to populate the history."
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <div class="footer">

    <b>PHISHGUARD</b> — Machine Learning URL Threat Analysis System

    <br><br>

    This project is an educational cybersecurity prototype.
    Its risk estimates are based on URL-level features and a model
    trained on a synthetic dataset. A high or low score should not
    be treated as definitive proof that a website is malicious or safe.

    <br><br>

    Built for cybersecurity, machine learning and threat-analysis
    portfolio demonstration.

    </div>
    """,
    unsafe_allow_html=True
)
