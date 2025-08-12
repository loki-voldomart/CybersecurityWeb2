#!/bin/bash

set -e

echo "🚀 Deploying Enterprise Cybersecurity Platform"

# Configuration
ENVIRONMENT=${1:-production}
VERSION=${2:-latest}

echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"

# Create necessary directories
mkdir -p logs data models ssl config

# Generate SSL certificates if they don't exist
if [ ! -f ssl/cert.pem ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=cybersec-platform"
fi

# Load environment variables
if [ -f ".env.$ENVIRONMENT" ]; then
    export $(cat .env.$ENVIRONMENT | xargs)
else
    echo "Warning: .env.$ENVIRONMENT file not found"
fi

# Build and deploy based on environment
case $ENVIRONMENT in
    "production")
        echo "🏭 Production deployment"
        
        # Build production images
        docker build -t cybersec-platform:$VERSION .
        
        # Deploy with Docker Compose
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
        
        # Wait for services to be ready
        echo "Waiting for services to start..."
        sleep 30
        
        # Run database migrations
        docker-compose exec cybersec-platform npm run db:migrate
        
        # Load ML models
        docker-compose exec cybersec-platform python3 ml_engine/train_models.py
        
        echo "✅ Production deployment complete"
        ;;
        
    "kubernetes")
        echo "☸️ Kubernetes deployment"
        
        # Build and push to registry
        docker build -t cybersec-platform:$VERSION .
        docker tag cybersec-platform:$VERSION your-registry/cybersec-platform:$VERSION
        docker push your-registry/cybersec-platform:$VERSION
        
        # Apply Kubernetes manifests
        kubectl apply -f kubernetes/
        
        # Wait for rollout
        kubectl rollout status deployment/cybersec-platform
        
        echo "✅ Kubernetes deployment complete"
        ;;
        
    "development")
        echo "🔧 Development deployment"
        docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
        echo "✅ Development environment ready"
        ;;
        
    *)
        echo "❌ Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

# Health check
echo "🏥 Running health checks..."
sleep 10

if curl -f http://localhost:3000/api/health > /dev/null 2>&1; then
    echo "✅ Platform is healthy"
else
    echo "❌ Health check failed"
    exit 1
fi

# Display access information
echo ""
echo "🌐 Access Information:"
echo "   Dashboard: https://localhost"
echo "   API: https://localhost/api"
echo "   Grafana: http://localhost:3001"
echo "   Kibana: http://localhost:5601"
echo ""
echo "📊 Monitoring:"
echo "   Prometheus: http://localhost:9090"
echo "   Logs: docker-compose logs -f"
echo ""
echo "🛑 To stop: docker-compose down"
