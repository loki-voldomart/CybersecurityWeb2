#!/bin/bash

echo "🚀 Starting Professional Network Monitoring System"
echo "=================================================="

# Check if running as root (required for packet capture)
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root for packet capture"
    echo "Please run: sudo $0"
    exit 1
fi

# Activate virtual environment
if [ -d "cybersec_ml_env" ]; then
    source cybersec_ml_env/bin/activate
    echo "✅ Activated ML environment"
else
    echo "❌ ML environment not found. Run setup_ml_environment.sh first"
    exit 1
fi

# Check if models are trained
if [ ! -d "trained_models" ] || [ ! -f "trained_models/metadata.pkl" ]; then
    echo "⚠️  No trained models found. Training models first..."
    python ml_engine/train_models.py
fi

# Get network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "🌐 Using network interface: $INTERFACE"

# Create logs directory
mkdir -p logs

# Start network monitoring
echo "🔍 Starting network packet capture and threat analysis..."
echo "Press Ctrl+C to stop monitoring"

python network_monitor/network_analyzer.py \
    --interface $INTERFACE \
    --duration 3600 \
    2>&1 | tee logs/network_monitoring_$(date +%Y%m%d_%H%M%S).log

echo "✅ Network monitoring completed"
