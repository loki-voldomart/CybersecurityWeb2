#!/bin/bash

echo "🚀 Starting Professional Attack Simulation Environment"
echo "====================================================="

# Check if running as root (required for packet generation)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Attack simulation requires root privileges for packet generation"
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

# Create attack simulation directories
mkdir -p logs/attacks
mkdir -p attack_data

# Initialize attack simulation
python -c "
from attack_simulation.attack_orchestrator import AttackOrchestrator
orchestrator = AttackOrchestrator()
print('✅ Attack simulation environment initialized')

# Create realistic attack scenarios
campaign_id = orchestrator.create_realistic_attack_scenarios()
print(f'✅ Created realistic attack campaign: {campaign_id}')

# Start orchestration
orchestrator.start_orchestration()
print('✅ Attack orchestration started')

print('🔴 RED TEAM ENVIRONMENT ACTIVE')
print('Attack simulation is now generating realistic threats')
print('Monitor the blue team defense systems for detection and response')
print('Press Ctrl+C to stop attack simulation')

try:
    import time
    while True:
        status = orchestrator.get_orchestration_status()
        print(f'Active scenarios: {status[\"active_scenarios\"]}, Queued: {status[\"queued_scenarios\"]}')
        time.sleep(30)
except KeyboardInterrupt:
    print('\\nStopping attack simulation...')
    orchestrator.stop_orchestration()
    print('✅ Attack simulation stopped')
"

echo "🔴 Attack simulation environment ready"
echo "Use this to test your blue team defense capabilities"
