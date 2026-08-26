import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import os

class FTAGPathPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        self.is_trained = False
        self.model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', 'ftag_ai_model.joblib')
        
    def train(self, data_path):
        print(f"Loading training data from {data_path}...")
        df = pd.read_csv(data_path)
        
        features = ['path_length', 'tac_width', 'dwell_lower_s', 'propagation_v', 'privilege_score']
        X = df[features]
        y = df['is_true_path']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        print("Training RandomForest model...")
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        
        print("\n--- Model Evaluation ---")
        print(classification_report(y_test, y_pred))
        print(f"ROC AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
        
        # Save model
        joblib.dump(self.model, self.model_path)
        print(f"Model saved to {self.model_path}")
        
    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            return True
        return False
        
    def predict_path_probability(self, path_length, tac_width, dwell_lower_s, propagation_v, privilege_score):
        if not self.is_trained:
            if not self.load_model():
                raise RuntimeError("Model is not trained and could not be loaded.")
                
        features = pd.DataFrame([{
            'path_length': path_length,
            'tac_width': tac_width,
            'dwell_lower_s': dwell_lower_s,
            'propagation_v': propagation_v,
            'privilege_score': privilege_score
        }])
        
        prob = self.model.predict_proba(features)[0][1]
        return prob

if __name__ == "__main__":
    predictor = FTAGPathPredictor()
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', 'synthetic_ai_training_data.csv')
    predictor.train(data_file)
