import streamlit as st
import pandas as pd
import numpy as np
import re

from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier


# ============================================================
# PHISHGUARD — THREAT INTELLIGENCE WEB APP
# ============================================================

st.set_page_config(
    page_title="PhishGuard | Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM DARK CYBERSECURITY DESIGN
# ============================================================

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(0, 180, 255, 0.08), transparent 30%),
        radial-gradient(circle at 90% 20%, rgba(0, 120, 255, 0.06), transparent 30%),
        #070b12;
    color: #e6edf3;
}

.block-container {
    padding-top: 2rem;
    max-width: 1400px;
}

h1, h2, h3 {
    color: #f1f5f9 !important;
}

.phishguard-header {
    padding: 20px 0 10px 0;
}

.logo {
    font-size: 34px;
    font-weight: 800;
    letter-spacing: 1px;
}

.logo span {
    color: #00d4ff;
}

.subtitle {
    color: #7f8ea3;
    font-size: 14px;
    margin-top: -8px;
}

.intel-card {
    background: rgba(15, 23, 36, 0.88);
    border: 1px solid rgba(0, 212, 255, 0.16);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 18px;
}

.metric-card {
    background: rgba(12, 20, 32, 0.95);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 12px;
    padding: 20px;
    min-height: 120px;
}

.metric-title {
    color: #7f8ea3;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    color: #f8fafc;
    font-size: 28px;
    font-weight: 750;
    margin-top: 8px;
}

.threat-low {
    color: #22c55e;
    font-weight: 800;
}

.threat-medium {
    color: #f59e0b;
    font-weight: 800;
}

.threat-high {
    color: #ef4444;
    font-weight: 800;
}

.section-title {
    font-size: 13px;
    color: #00d4ff;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 700;
    margin-bottom: 10px;
}

.url-box {
    background: #0b111c;
    border: 1px solid rgba(0, 212, 255, 0.25);
    border-radius: 10px;
    padding: 14px;
}

.indicator {
    background: #0c1420;
    border-radius: 10px;
    padding: 14px;
    margin-bottom: 8px;
    border: 1px solid rgba(255,255,255,0.05);
}

.footer {
    color: #64748b;
    text-align: center;
    padding: 30px 0 10px 0;
    font-size: 12px;
}

div.stButton > button {
    width: 100%;
    background: #00a8cc;
    color: white;
    border: none;
    border-radius: 9px;
    padding: 10px;
    font-weight: 700;
}

div.stButton > button:hover {
    background: #00c4ed;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="phishguard-header">
    <div class="logo">🛡️ <span>PHISH</span>GUARD</div>
    <div class="subtitle">
        MACHINE LEARNING • URL THREAT INTELLIGENCE • RISK ANALYSIS
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ============================================================
# LOAD DATASET
# ============================================================

@st.cache_data
def load_dataset():
    return pd.read_csv("phishguard_dataset.csv")


df = load_dataset()


# ============================================================
# TRAIN MODEL
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

        "https": int(url.lower().startswith("https://")),

        "has_ip": int(bool(
            re.search(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                hostname
            )
        )),

        "dot_count": url.count("."),

        "hyphen_count": url.count("-"),

        "at_count": url.count("@"),

        "digit_count": sum(c.isdigit() for c in url),

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
            any(shortener in hostname for shortener in shorteners)
        )
    }


# ============================================================
# RISK ANALYSIS
# ============================================================

def analyze_url(url):

    features = extract_features(url)

    feature_df = pd.DataFrame(
        [features],
        columns=FEATURES
    )

    prediction = model.predict(feature_df)[0]

    probabilities = model.predict_proba(feature_df)[0]

    suspicious_index = list(
        model.classes_
    ).index(1)

    probability = probabilities[suspicious_index]

    risk_score = round(probability * 100)

    if risk_score < 30:
        risk_level = "LOW RISK"
        risk_class = "threat-low"

    elif risk_score < 70:
        risk_level = "MEDIUM RISK"
        risk_class = "threat-medium"

    else:
        risk_level = "HIGH RISK"
        risk_class = "threat-high"

    return (
        features,
        prediction,
        probability,
        risk_score,
        risk_level,
        risk_class
    )


# ============================================================
# THREAT EXPLANATION
# ============================================================

def explain_features(url, features):

    indicators = []

    if features["https"] == 0:
        indicators.append(
            ("⚠️", "HTTPS", "Connection does not use HTTPS")
        )
    else:
        indicators.append(
            ("✓", "HTTPS", "Secure protocol detected")
        )

    if features["has_ip"]:
        indicators.append(
            ("⚠️", "IP Address", "URL contains an IP address")
        )
    else:
        indicators.append(
            ("✓", "IP Address", "No direct IP address detected")
        )

    if features["suspicious_word_count"] > 0:
        indicators.append(
            (
                "⚠️",
                "Suspicious Keywords",
                f"{features['suspicious_word_count']} suspicious keyword(s) detected"
            )
        )
    else:
        indicators.append(
            ("✓", "Suspicious Keywords", "No known suspicious keywords detected")
        )

    if features["url_length"] > 75:
        indicators.append(
            ("⚠️", "URL Length", "Unusually long URL")
        )
    else:
        indicators.append(
            ("✓", "URL Length", "URL length appears normal")
        )

    if features["hyphen_count"] >= 3:
        indicators.append(
            ("⚠️", "Hyphens", "Multiple hyphens detected")
        )
    else:
        indicators.append(
            ("✓", "Hyphens", "No unusual number of hyphens")
        )

    if features["at_count"] > 0:
        indicators.append(
            ("⚠️", "@ Symbol", "@ symbol detected in URL")
        )
    else:
        indicators.append(
            ("✓", "@ Symbol", "No @ symbol detected")
        )

    return indicators


# ============================================================
# URL ANALYZER
# ============================================================

st.markdown(
    '<div class="section-title">URL THREAT ANALYZER</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="intel-card">',
    unsafe_allow_html=True
)

url = st.text_input(
    "Enter URL for analysis",
    placeholder="https://example.com/login"
)

analyze_button = st.button(
    "🔍 ANALYZE THREAT"
)

st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# RESULTS
# ============================================================

if analyze_button:

    if not url.strip():

        st.warning("Please enter a URL for analysis.")

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

            indicators = explain_features(
                url,
                features
            )

            # ------------------------------------------------
            # URL DISPLAY
            # ------------------------------------------------

            st.markdown(
                f"""
                <div class="intel-card">
                    <div class="section-title">ANALYZED TARGET</div>
                    <div style="font-size:16px; color:#cbd5e1;">
                        {url}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # ------------------------------------------------
            # METRICS
            # ------------------------------------------------

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-title">
                            Threat Score
                        </div>
                        <div class="metric-value">
                            {risk_score}/100
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with col2:

                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-title">
                            Risk Level
                        </div>
                        <div class="metric-value {risk_class}">
                            {risk_level}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with col3:

                classification = (
                    "SUSPICIOUS"
                    if prediction == 1
                    else "LOW CONCERN"
                )

                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-title">
                            Classification
                        </div>
                        <div class="metric-value">
                            {classification}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with col4:

                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-title">
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
            # TWO-COLUMN INTELLIGENCE PANEL
            # ------------------------------------------------

            left, right = st.columns(2)

            with left:

                st.markdown(
                    '<div class="section-title">SECURITY INDICATORS</div>',
                    unsafe_allow_html=True
                )

                for icon, title, message in indicators:

                    st.markdown(
                        f"""
                        <div class="indicator">
                            <strong>{icon} {title}</strong>
                            <br>
                            <span style="color:#7f8ea3;">
                                {message}
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )


            with right:

                st.markdown(
                    '<div class="section-title">URL INTELLIGENCE</div>',
                    unsafe_allow_html=True
                )

                intelligence = {
                    "URL Length": features["url_length"],
                    "HTTPS": "Enabled" if features["https"] else "Not detected",
                    "IP Address": "Detected" if features["has_ip"] else "Not detected",
                    "Subdomains": features["subdomain_count"],
                    "Hyphens": features["hyphen_count"],
                    "Digits": features["digit_count"],
                    "Special Characters": features["special_char_count"],
                    "Suspicious Keywords": features["suspicious_word_count"]
                }

                for key, value in intelligence.items():

                    st.markdown(
                        f"""
                        <div class="indicator">
                            <strong>{key}</strong>
                            <span style="float:right;color:#cbd5e1;">
                                {value}
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )


            # ------------------------------------------------
            # MODEL INFORMATION
            # ------------------------------------------------

            st.write("")

            st.markdown(
                """
                <div class="intel-card">
                    <div class="section-title">
                        MACHINE LEARNING ANALYSIS
                    </div>

                    <p style="color:#94a3b8;">
                        PhishGuard uses a Random Forest classifier trained
                        on the project's synthetic URL dataset. The model
                        analyzes structural URL characteristics and produces
                        a probability-based risk estimate.
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

        except Exception as e:

            st.error(
                f"Unable to analyze this URL: {str(e)}"
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        🛡️ PHISHGUARD • MACHINE-LEARNING-BASED URL RISK ANALYSIS
        <br>
        Educational cybersecurity prototype • Synthetic dataset
    </div>
    """,
    unsafe_allow_html=True
)
