🛡️ PhishGuard — Phishing URL Detection & Risk Analysis

PhishGuard is a machine-learning-based cybersecurity prototype designed to analyze URLs and estimate their potential phishing risk.

The project extracts structural and security-related characteristics from URLs, applies machine-learning models for classification, and provides an interactive interface for analyzing URLs.

Note: This project uses a synthetic dataset for educational and portfolio purposes. It is a prototype and should not be considered a production-grade phishing detection system.

⸻

🎯 Project Objectives

* Detect potentially suspicious URLs using machine-learning techniques.
* Extract meaningful security-related URL features.
* Compare multiple classification models.
* Generate a model-based phishing risk score.
* Provide rule-based explanations for suspicious URL characteristics.
* Build an interactive interface for URL analysis.

⸻

🧠 Machine Learning Models

The project trains and compares three classification algorithms:

* Logistic Regression
* Decision Tree
* Random Forest

Models are evaluated using:

* Accuracy
* Precision
* Recall
* F1-Score
* Confusion Matrix

⸻

🔍 URL Feature Engineering

PhishGuard extracts multiple characteristics from URLs, including:

* URL length
* HTTPS usage
* IP address presence
* Suspicious keyword presence
* Number of hyphens
* Number of subdomains
* @ symbol presence
* URL shortener indicators
* Other structural URL characteristics

These features are converted into numerical values and supplied to the machine-learning models.

⸻

⚙️ Project Architecture

User URL
   ↓
URL Feature Extraction
   ↓
Feature Engineering
   ↓
Machine Learning Model
   ↓
Prediction Probability
   ↓
Risk Score
   ↓
Risk Classification
   ↓
Security Explanation

⸻

🖥️ Interactive Dashboard

PhishGuard includes an interactive Gradio dashboard with three main sections:

URL Analyzer

Allows users to enter a URL and receive:

* Classification
* Risk score
* Risk level
* Suspicious indicators

Model Performance

Displays the performance comparison of the trained machine-learning models.

Feature Importance

Shows which URL characteristics contributed most to the Random Forest model’s predictions.

⸻

🛠️ Technologies Used

* Python
* Pandas
* NumPy
* Scikit-learn
* Matplotlib
* Seaborn
* Gradio
* Google Colab
* GitHub

⸻

📊 Dataset

The project uses a synthetically generated dataset containing approximately 1,000 URL examples.

The dataset was created specifically for this educational prototype and contains examples representing legitimate and suspicious URL patterns.

It is not a collection of verified real-world phishing URLs.

⸻

🚀 How to Run

1. Clone the repository

git clone https://github.com/YOUR-USERNAME/PhishGuard.git
cd PhishGuard

2. Install dependencies

pip install -r requirements.txt

3. Open the notebook

Open:

PhishGuard_Phishing_URL_Detection.ipynb

The notebook can be run using Google Colab or a local Jupyter environment.

⸻

📁 Repository Structure

PhishGuard/
│
├── PhishGuard_Phishing_URL_Detection.ipynb
├── phishguard_dataset.csv
├── requirements.txt
└── README.md

⸻

⚠️ Limitations

This project is a cybersecurity learning and portfolio prototype.

It does not currently perform:

* DNS reputation analysis
* WHOIS analysis
* Real-time threat intelligence lookup
* SSL certificate verification
* Website content analysis
* Domain-age verification
* Browser-based sandbox analysis
* Real-world phishing database validation

Because the dataset is synthetic, model performance should not be interpreted as production-level phishing detection accuracy.

⸻

🔮 Future Improvements

Possible future improvements include:

* Integration with real phishing datasets
* Real-time threat intelligence APIs
* DNS and WHOIS analysis
* SSL certificate analysis
* Domain reputation scoring
* Website-content analysis
* Explainable AI techniques
* REST API deployment
* Cloud deployment
* Browser extension integration

⸻

👨‍💻 Project Purpose

This project was developed as a software engineering and cybersecurity portfolio project to demonstrate practical experience with:

* Python programming
* Data preprocessing
* Feature engineering
* Machine learning
* Model evaluation
* Data visualization
* Cybersecurity concepts
* Interactive application development

⸻

📜 Disclaimer

PhishGuard is an educational prototype. Its predictions should not be treated as definitive evidence that a URL is safe or malicious. Always verify suspicious links using trusted security resources before interacting with them.
