#!/bin/bash

echo "🛡️ Installing Enterprise Cybersecurity Platform"

# Check system requirements
check_requirements() {
    echo "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is required but not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo "❌ Docker Compose is required but not installed"
        exit 1
    fi
    
    # Check system resources
    MEMORY=$(free -g | awk '/^Mem:/{print $2}')
    if [ $MEMORY -lt 8 ]; then
        echo "⚠️ Warning: Minimum 8GB RAM recommended, found ${MEMORY}GB"
    fi
    
    echo "✅ System requirements check passed"
}

# Setup environment
setup_environment() {
    echo "Setting up environment..."
    
    # Create environment file if it doesn't exist
    if [ ! -f .env.production ]; then
        cat > .env.production << EOF
# Database Configuration
POSTGRES_USER=cybersec_admin
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_DB=cybersecurity

# Redis Configuration
REDIS_PASSWORD=$(openssl rand -base64 32)

# Supabase Configuration (Update with your values)
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password

# Monitoring
GRAFANA_PASSWORD=$(openssl rand -base64 16)

# Security
JWT_SECRET=$(openssl rand -base64 64)
ENCRYPTION_KEY=$(openssl rand -base64 32)
EOF
        echo "📝 Created .env.production file - please update with your values"
    fi
    
    # Create necessary directories
    mkdir -p {logs,data,models,ssl,config/grafana}
    
    echo "✅ Environment setup complete"
}

# Install and configure
install_platform() {
    echo "Installing cybersecurity platform..."
    
    # Build the platform
    docker build -t cybersec-platform:latest .
    
    # Start services
    docker-compose up -d
    
    # Wait for services
    echo "Waiting for services to start..."
    sleep 60
    
    # Initialize database
    echo "Initializing database..."
    docker-compose exec -T cybersec-platform npm run db:setup
    
    # Train ML models
    echo "Training ML models..."
    docker-compose exec -T cybersec-platform python3 ml_engine/train_models.py
    
    echo "✅ Platform installation complete"
}

# Main installation process
main() {
    echo "🚀 Starting installation process..."
    
    check_requirements
    setup_environment
    install_platform
    
    echo ""
    echo "🎉 Installation Complete!"
    echo ""
    echo "🌐 Access your cybersecurity platform at:"
    echo "   Dashboard: https://localhost"
    echo "   Grafana: http://localhost:3001"
    echo "   Kibana: http://localhost:5601"
    echo ""
    echo "📚 Next steps:"
    echo "   1. Update .env.production with your Supabase credentials"
    echo "   2. Configure email settings for alerts"
    echo "   3. Review security settings in config/"
    echo "   4. Set up SSL certificates for production"
    echo ""
    echo "📖 Documentation: ./docs/README.md"
    echo "🛑 To stop: docker-compose down"
}

main "$@"
