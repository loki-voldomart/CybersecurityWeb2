#!/bin/bash

echo "🚀 Starting Enterprise Cybersecurity Monitoring System"

# Create necessary directories
mkdir -p logs
mkdir -p data/analytics
mkdir -p data/reports

# Set up Python environment
echo "Setting up Python environment..."
python3 -m venv monitoring_env
source monitoring_env/bin/activate
pip install -r monitoring/requirements.txt

# Start monitoring components
echo "Starting real-time monitoring..."
python3 monitoring/real_time_monitor.py &
MONITOR_PID=$!

echo "Starting analytics engine..."
python3 monitoring/analytics_engine.py &
ANALYTICS_PID=$!

# Start the web dashboard
echo "Starting web dashboard..."
npm run dev &
WEB_PID=$!

echo "✅ Monitoring system started successfully!"
echo "📊 Dashboard: http://localhost:3000"
echo "🔍 Real-time Monitor PID: $MONITOR_PID"
echo "📈 Analytics Engine PID: $ANALYTICS_PID"
echo "🌐 Web Dashboard PID: $WEB_PID"

# Create stop script
cat > stop_monitoring.sh << EOF
#!/bin/bash
echo "Stopping monitoring system..."
kill $MONITOR_PID $ANALYTICS_PID $WEB_PID
echo "✅ Monitoring system stopped"
EOF

chmod +x stop_monitoring.sh

echo "To stop the system, run: ./stop_monitoring.sh"

# Keep script running
wait
