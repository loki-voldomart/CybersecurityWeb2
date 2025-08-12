#!/bin/bash

# Network Traffic Simulation Runner
# This script sets up and runs the network traffic simulation

echo "🚀 Starting Cybersecurity Network Simulation..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Install required Python packages
echo "📦 Installing Python dependencies..."
pip3 install -r scripts/requirements.txt

# Set simulation duration (default: 30 minutes)
export SIMULATION_DURATION=${1:-30}

echo "⏱️  Simulation will run for $SIMULATION_DURATION minutes"
echo "🌐 Make sure your Next.js server is running on http://localhost:3000"

# Run the main network simulator
echo "🔄 Starting network traffic simulation..."
python3 scripts/network_simulator.py &
SIMULATOR_PID=$!

# Wait a few seconds, then run attack scenarios
sleep 5
echo "⚔️  Launching attack scenarios..."
python3 scripts/attack_scenarios.py &
SCENARIOS_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🛑 Stopping simulation..."
    kill $SIMULATOR_PID 2>/dev/null
    kill $SCENARIOS_PID 2>/dev/null
    echo "✅ Simulation stopped"
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Wait for simulation to complete
wait $SIMULATOR_PID
wait $SCENARIOS_PID

echo "🏁 Network simulation completed successfully!"
