#!/bin/bash

# AI/ML Threat Detection Startup Script
echo "🤖 Starting AI/ML Threat Detection System..."

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Install ML dependencies
echo "📦 Installing ML dependencies..."
pip3 install -r scripts/ml_requirements.txt

# Train initial models
echo "🧠 Training initial ML models..."
python3 scripts/threat_detection_engine.py

# Start real-time analysis
echo "🔄 Starting real-time threat analysis..."
python3 scripts/real_time_analyzer.py &
ANALYZER_PID=$!

echo "✅ AI/ML Threat Detection System is running!"
echo "📊 Models will continuously learn from new network traffic"
echo "🎯 High-confidence threats will automatically create alerts"

# Cleanup function
cleanup() {
    echo "🛑 Stopping AI analysis..."
    kill $ANALYZER_PID 2>/dev/null
    echo "✅ AI analysis stopped"
}

trap cleanup EXIT

# Keep script running
wait $ANALYZER_PID
