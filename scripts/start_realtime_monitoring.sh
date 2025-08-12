#!/bin/bash

# Real-time Monitoring System Startup Script
echo "🔄 Starting Real-time Cybersecurity Monitoring System..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

# Install WebSocket server dependencies
echo "📦 Installing WebSocket server dependencies..."
cd scripts
npm install --package-lock-only --package-lock-file websocket_package.json
npm install ws @supabase/supabase-js

# Start WebSocket server
echo "🚀 Starting WebSocket server on port 3001..."
node websocket_server.js &
WEBSOCKET_PID=$!

echo "✅ Real-time monitoring system is running!"
echo "📡 WebSocket server: ws://localhost:3001"
echo "🔄 Dashboard will receive live updates automatically"
echo "📊 Real-time features:"
echo "  • Live threat event updates"
echo "  • Real-time network statistics"
echo "  • System status monitoring"
echo "  • Automatic dashboard refresh"

# Cleanup function
cleanup() {
    echo "🛑 Stopping real-time monitoring..."
    kill $WEBSOCKET_PID 2>/dev/null
    echo "✅ Real-time monitoring stopped"
}

trap cleanup EXIT

# Keep script running
wait $WEBSOCKET_PID
