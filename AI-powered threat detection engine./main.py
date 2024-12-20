import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from typing import Tuple, Dict, Any
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    AI-based threat detection system using Random Forest classifier.
    Handles data preprocessing, model training, and threat prediction.
    """
    
    def __init__(self, model_path: str = 'threat_detector_model.joblib'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def preprocess_data(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Preprocess network traffic data for training/prediction.
        
        Args:
            data: Raw network traffic data
            
        Returns:
            Tuple of processed features and labels
        """
        try:
            # Drop any missing values
            data = data.dropna()
            
            # Store feature columns for later use
            self.feature_columns = [col for col in data.columns 
                                  if col not in ['label', 'attack_type']]
            
            # Extract features and labels
            X = data[self.feature_columns]
            y = data['label'] if 'label' in data.columns else None
            
            # Scale features
            X = pd.DataFrame(
                self.scaler.fit_transform(X),
                columns=self.feature_columns
            )
            
            logger.info(f"Preprocessed {len(X)} samples with {len(self.feature_columns)} features")
            return X, y
            
        except Exception as e:
            logger.error(f"Error in data preprocessing: {str(e)}")
            raise
            
    def train(self, training_data: pd.DataFrame, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the threat detection model.
        
        Args:
            training_data: DataFrame containing network traffic data
            test_size: Proportion of data to use for testing
            
        Returns:
            Dictionary containing model performance metrics
        """
        try:
            logger.info("Starting model training...")
            
            # Preprocess data
            X, y = self.preprocess_data(training_data)
            
            # Split into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42
            )
            
            # Initialize and train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test)
            metrics = {
                'classification_report': classification_report(y_test, y_pred),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            # Save model and scaler
            self.save_model()
            
            logger.info("Model training completed successfully")
            return metrics
            
        except Exception as e:
            logger.error(f"Error in model training: {str(e)}")
            raise
            
    def predict(self, network_data: pd.DataFrame) -> np.ndarray:
        """
        Predict threats in new network traffic data.
        
        Args:
            network_data: DataFrame containing new network traffic data
            
        Returns:
            Array of predicted labels
        """
        try:
            if self.model is None:
                self.load_model()
                
            # Preprocess new data
            X, _ = self.preprocess_data(network_data)
            
            # Make predictions
            predictions = self.model.predict(X)
            probabilities = self.model.predict_proba(X)
            
            # Combine predictions with probabilities
            results = []
            for pred, prob in zip(predictions, probabilities):
                results.append({
                    'prediction': int(pred),
                    'confidence': float(max(prob)),
                    'timestamp': pd.Timestamp.now().isoformat()
                })
                
            return results
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            raise
            
    def save_model(self):
        """Save the trained model and scaler to disk."""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns
            }
            joblib.dump(model_data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise
            
    def load_model(self):
        """Load the trained model and scaler from disk."""
        try:
            model_data = joblib.load(self.model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            logger.info(f"Model loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

# Example usage
if __name__ == "__main__":
    # Load sample network traffic data (replace with actual data source)
    sample_data = pd.read_csv("network_traffic.csv")
    
    # Initialize and train detector
    detector = ThreatDetector()
    metrics = detector.train(sample_data)
    
    # Print training metrics
    print("\nTraining Metrics:")
    print(json.dumps(metrics, indent=2))
    
    # Make predictions on new data
    new_data = pd.read_csv("new_traffic.csv")
    predictions = detector.predict(new_data)
    
    # Print predictions
    print("\nPredictions:")
    print(json.dumps(predictions[:5], indent=2))
