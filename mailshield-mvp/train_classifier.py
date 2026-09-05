"""
train_classifier.py

Trains a simple, explainable TF-IDF + Logistic Regression phishing/BEC text
classifier on data/training_data.csv and saves the pipeline to core/model.pkl.

Intentionally simple: for a hackathon MVP we want something that runs
instantly, trains in under a second, and whose coefficients we can inspect
to explain *why* it flagged something (see core/classifier.py's top_words).
"""

import pandas as pd
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(__file__)
DATA_PATH = os.path.join(HERE, "data", "training_data.csv")
MODEL_PATH = os.path.join(HERE, "core", "model.pkl")


def main():
    df = pd.read_csv(DATA_PATH)
    X = df["text"]
    y = (df["label"] == "phishing").astype(int)  # 1 = phishing/BEC, 0 = legitimate

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(stop_words="english", max_features=500, ngram_range=(1, 2))),
        ("clf", LogisticRegression(max_iter=1000)),
    ])
    pipeline.fit(X, y)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)

    train_acc = pipeline.score(X, y)
    print(f"Trained on {len(df)} examples. Training accuracy: {train_acc:.2%}")
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
