#!/bin/bash

echo "🚀 Setting up Professional ML Environment for Cybersecurity Platform"
echo "=================================================================="

# Create virtual environment
echo "📦 Creating Python virtual environment..."
python3 -m venv cybersec_ml_env
source cybersec_ml_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install core ML libraries
echo "🤖 Installing machine learning libraries..."
pip install numpy pandas scikit-learn

# Install deep learning libraries
echo "🧠 Installing deep learning libraries..."
pip install tensorflow torch

# Install data processing libraries
echo "📊 Installing data processing libraries..."
pip install matplotlib seaborn plotly

# Install networking libraries
echo "🌐 Installing networking libraries..."
pip install scapy psutil netifaces

# Install utility libraries
echo "🔧 Installing utility libraries..."
pip install requests joblib tqdm

# Install cybersecurity specific libraries
echo "🛡️ Installing cybersecurity libraries..."
pip install cryptography

# Create requirements file
echo "📝 Creating requirements.txt..."
pip freeze > ml_engine/requirements.txt

echo "✅ ML environment setup complete!"
echo "To activate: source cybersec_ml_env/bin/activate"
echo "To train models: python ml_engine/train_models.py"
