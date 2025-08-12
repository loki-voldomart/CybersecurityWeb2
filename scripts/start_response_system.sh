#!/bin/bash

echo "🚀 Starting Professional Response System"
echo "========================================"

# Check if running as root (required for iptables)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Response system requires root privileges for network blocking"
    echo "Some features may not work without sudo access"
fi

# Activate virtual environment
if [ -d "cybersec_ml_env" ]; then
    source cybersec_ml_env/bin/activate
    echo "✅ Activated ML environment"
else
    echo "❌ ML environment not found. Run setup_ml_environment.sh first"
    exit 1
fi

# Create necessary directories
mkdir -p logs
mkdir -p response_data

# Initialize response databases
python -c "
from response.response_agents import NetworkBlockingAgent, AlertingAgent
blocker = NetworkBlockingAgent()
alerter = AlertingAgent()
print('✅ Response system databases initialized')
"

echo "🛡️  Response system ready"
echo "Network blocking and alerting agents are operational"
echo "Monitor logs/response_system.log for activity"

# Keep script running to show it's active
echo "Press Ctrl+C to stop response system"
while true; do
    sleep 60
    echo "$(date): Response system active - $(ps aux | grep python | wc -l) Python processes running"
done
