#!/usr/bin/env python3
"""
Professional ML Training Pipeline for Cybersecurity Platform
Trains models on real datasets with enterprise-grade accuracy
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dataset_loader import CybersecurityDatasetLoader
from threat_models import ProfessionalThreatDetectionModels
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Main training pipeline"""
    print("🚀 Starting Professional Cybersecurity ML Training Pipeline")
    print("=" * 60)
    
    # Initialize components
    dataset_loader = CybersecurityDatasetLoader()
    model_trainer = ProfessionalThreatDetectionModels()
    
    try:
        # Step 1: Load and prepare training data
        print("\n📊 Loading and preparing training data...")
        training_data = dataset_loader.prepare_training_data('kdd99')
        
        print(f"✅ Training set: {training_data['X_train'].shape[0]} samples")
        print(f"✅ Test set: {training_data['X_test'].shape[0]} samples")
        print(f"✅ Features: {len(training_data['feature_names'])}")
        print(f"✅ Attack types: {training_data['attack_types']}")
        
        # Step 2: Train ensemble models
        print("\n🤖 Training ensemble models for maximum accuracy...")
        results = model_trainer.train_ensemble_model(training_data)
        
        # Step 3: Train specialized detectors
        print("\n🎯 Training specialized attack detectors...")
        specialized = model_trainer.train_specialized_detectors(training_data)
        
        # Step 4: Display results
        print("\n📈 TRAINING RESULTS")
        print("=" * 40)
        
        for model_name, metrics in results.items():
            accuracy = metrics['accuracy']
            cv_mean = metrics['cv_mean']
            cv_std = metrics['cv_std']
            
            print(f"{model_name.upper()}:")
            print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
            print(f"  Cross-validation: {cv_mean:.4f} ± {cv_std:.4f}")
            print(f"  Best params: {metrics['best_params']}")
            print()
        
        print(f"✅ Specialized detectors trained: {list(specialized.keys())}")
        
        # Step 5: Test inference
        print("\n🧪 Testing inference pipeline...")
        
        # Create sample network features for testing
        sample_features = training_data['X_test'].iloc[0].values
        prediction_result = model_trainer.predict_threat(sample_features)
        
        print("Sample prediction:")
        print(f"  Prediction: {prediction_result['prediction']}")
        print(f"  Confidence: {prediction_result['confidence']:.4f}")
        print(f"  Threat Level: {prediction_result['threat_level']}")
        
        print("\n🎉 Training pipeline completed successfully!")
        print("Models saved to 'trained_models/' directory")
        
        # Calculate overall system accuracy
        best_accuracy = max([r['accuracy'] for r in results.values()])
        print(f"\n🏆 Best Model Accuracy: {best_accuracy:.4f} ({best_accuracy*100:.2f}%)")
        
        if best_accuracy >= 0.95:
            print("✅ ENTERPRISE-GRADE ACCURACY ACHIEVED (95%+)")
        elif best_accuracy >= 0.90:
            print("⚠️  Good accuracy achieved (90%+), consider hyperparameter tuning")
        else:
            print("❌ Accuracy below 90%, requires optimization")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
