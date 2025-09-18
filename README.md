# 🔒 SecureDLP - AI-Powered Data Leak Prevention System

**SecureDLP** is an automated Data Leak Prevention (DLP) tool designed to protect organizations from internal data leaks. It leverages a combination of regex patterns, machine learning, and a powerful policy engine to scan files and emails in real-time, classify their sensitivity, and enforce protective actions.

## 🚀 Features

### 🔍 Core DLP Capabilities
- **Multi-Format File Scanning**: Extract and analyze text from TXT, PDF, and Word DOCX documents
- **Real-Time Email Protection**: Scan outbound email content and attachments before sending
- **Comprehensive Pattern Detection**: Identify sensitive data including SSN, Credit Cards, API Keys, Passwords, and more

### 🤖 Advanced AI & ML Integration
- **Zero-Shot Classification**: Uses Hugging Face's model to detect sensitive content without prior training
- **Explainable AI (XAI)**: Incorporates LIME to explain why content was flagged as sensitive
- **Flexible Model Support**: Supports both custom-trained models and zero-shot learning

### ⚙️ Policy & Management
- **Automated Policy Engine**: Enforces real-time actions (Block, Quarantine, Alert, Monitor)
- **Centralized Dashboard**: View system health, alerts, and risk metrics
- **Detailed Audit Logging**: Maintains comprehensive logs for compliance and analysis

### 📊 Reporting & Analytics
- **Interactive Visualizations**: Track detection trends and risk levels over time
- **Custom Report Generation**: Download detailed reports on DLP activity

## 🛠️ Tech Stack

- **Web Framework**: Streamlit
- **AI Model**: Hugging Face Transformers (facebook/bart-large-mnli)
- **Explainable AI**: LIME
- **File Processing**: PyPDF2, python-docx
- **Machine Learning**: scikit-learn, TensorFlow
- **Data Handling**: pandas, numpy

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Dhanya125/dlp-prototype.git
cd secureDLP
```
### 2. Create Virtual Environment
python -m venv venv

### 3. Activate Virtual Environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

### 4. Install Dependencies
pip install -r requirements.txt

### 5. Configure Environment Variables
# Create a .env file in the project root and add:
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your.email@gmail.com
SENDER_PASSWORD=your_app_specific_password

### 6. Run the Application
streamlit run app.py
