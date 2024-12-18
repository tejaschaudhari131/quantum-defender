import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

class AnomalyDetector:
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize Anomaly Detector with Isolation Forest algorithm
        
        Args:
            contamination (float): Expected proportion of outliers in the dataset
            random_state (int): Seed for reproducibility
        """
        self.scaler = StandardScaler()
        self.detector = IsolationForest(
            contamination=contamination, 
            random_state=random_state, 
            verbose=0
        )
        self.is_fitted = False
    
    def preprocess(self, X):
        """
        Preprocess input data by scaling features
        
        Args:
            X (numpy.ndarray or pandas.DataFrame): Input features
        
        Returns:
            numpy.ndarray: Scaled features
        """
        # Handle both numpy arrays and pandas DataFrames
        if isinstance(X, pd.DataFrame):
            X = X.values
        
        return self.scaler.fit_transform(X)
    
    def fit(self, X):
        """
        Fit the anomaly detection model
        
        Args:
            X (numpy.ndarray or pandas.DataFrame): Training data
        
        Returns:
            self: Fitted model instance
        """
        # Preprocess and fit the Isolation Forest
        X_scaled = self.preprocess(X)
        self.detector.fit(X_scaled)
        self.is_fitted = True
        return self
    
    def predict(self, X):
        """
        Predict anomalies in the input data
        
        Args:
            X (numpy.ndarray or pandas.DataFrame): Input data to check for anomalies
        
        Returns:
            numpy.ndarray: Anomaly labels (-1 for anomalies, 1 for normal data)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        # Preprocess and predict
        X_scaled = self.scaler.transform(X)
        return self.detector.predict(X_scaled)
    
    def get_anomaly_scores(self, X):
        """
        Get anomaly scores for input data
        
        Args:
            X (numpy.ndarray or pandas.DataFrame): Input data
        
        Returns:
            numpy.ndarray: Anomaly scores
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before getting scores")
        
        X_scaled = self.scaler.transform(X)
        return -self.detector.score_samples(X_scaled)
    
    def visualize_anomalies(self, X, anomaly_labels):
        """
        Visualize anomalies using dimensionality reduction
        
        Args:
            X (numpy.ndarray or pandas.DataFrame): Original data
            anomaly_labels (numpy.ndarray): Anomaly labels
        """
        from sklearn.decomposition import PCA
        
        # Reduce dimensionality for visualization
        pca = PCA(n_components=2)
        X_reduced = pca.fit_transform(self.scaler.transform(X))
        
        # Create visualization
        plt.figure(figsize=(10, 6))
        plt.scatter(
            X_reduced[anomaly_labels == 1, 0], 
            X_reduced[anomaly_labels == 1, 1], 
            c='blue', 
            label='Normal', 
            alpha=0.7
        )
        plt.scatter(
            X_reduced[anomaly_labels == -1, 0], 
            X_reduced[anomaly_labels == -1, 1], 
            c='red', 
            label='Anomaly', 
            marker='x'
        )
        plt.title('Anomaly Detection Visualization')
        plt.xlabel('First Principal Component')
        plt.ylabel('Second Principal Component')
        plt.legend()
        plt.show()

# Example usage
def generate_sample_data():
    """
    Generate a synthetic dataset with some anomalies
    
    Returns:
        tuple: Training and testing datasets
    """
    # Generate normal data
    normal_data = np.random.normal(0, 1, (1000, 5))
    
    # Add some anomalies
    anomalies = np.random.normal(5, 2, (50, 5))
    
    # Combine datasets
    X = np.vstack([normal_data, anomalies])
    
    # Split into train and test
    return train_test_split(X, test_size=0.2, random_state=42)

# Demonstration
def main():
    # Generate sample data
    X_train, X_test, _, _ = generate_sample_data()
    
    # Initialize and train anomaly detector
    detector = AnomalyDetector(contamination=0.05)
    detector.fit(X_train)
    
    # Predict anomalies
    anomaly_labels = detector.predict(X_test)
    
    # Get anomaly scores
    anomaly_scores = detector.get_anomaly_scores(X_test)
    
    # Visualize anomalies
    detector.visualize_anomalies(X_test, anomaly_labels)
    
    # Print anomaly detection results
    print("Total test samples:", len(X_test))
    print("Detected anomalies:", np.sum(anomaly_labels == -1))
    print("Anomaly Scores (first 10):", anomaly_scores[:10])

if __name__ == "__main__":
    main()
