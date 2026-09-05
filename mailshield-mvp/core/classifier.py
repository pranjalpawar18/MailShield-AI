"""
classifier.py

Loads the trained TF-IDF + LogisticRegression pipeline and exposes:
    predict(text) -> {"label", "confidence", "top_words"}

"top_words" surfaces which words in the input most influenced the
phishing-direction score, using the model's learned coefficients. This is
what makes the score explainable to an analyst/judge rather than a black box.
"""

import os
import pickle
import numpy as np

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "model.pkl")

_pipeline = None


def _load_model():
    global _pipeline
    if _pipeline is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Run train_classifier.py first."
            )
        with open(MODEL_PATH, "rb") as f:
            _pipeline = pickle.load(f)
    return _pipeline


def predict(text: str) -> dict:
    pipeline = _load_model()
    vectorizer = pipeline.named_steps["tfidf"]
    clf = pipeline.named_steps["clf"]

    proba = pipeline.predict_proba([text])[0]
    phishing_confidence = float(proba[1]) * 100  # class 1 = phishing/BEC

    label = "phishing" if phishing_confidence >= 50 else "legitimate"

    # Explainability: which words in this text pushed toward phishing?
    tfidf_vector = vectorizer.transform([text])
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = clf.coef_[0]

    nonzero_idx = tfidf_vector.nonzero()[1]
    if len(nonzero_idx) > 0:
        contributions = tfidf_vector[0, nonzero_idx].toarray()[0] * coefs[nonzero_idx]
        order = np.argsort(-contributions)[:3]
        top_words = [feature_names[nonzero_idx[i]] for i in order if contributions[i] > 0]
    else:
        top_words = []

    return {
        "label": label,
        "confidence": round(phishing_confidence, 1),
        "top_words": top_words,
    }


if __name__ == "__main__":
    from header_forensics import analyze_eml
    import glob, os as _os

    for path in sorted(glob.glob(_os.path.join(HERE, "..", "data", "sample_emails", "*.eml"))):
        f = analyze_eml(path)
        text = f["subject"] + " " + f["body_text"]
        result = predict(text)
        print(f"{_os.path.basename(path):30s} label={result['label']:11s} "
              f"confidence={result['confidence']:5.1f}  top_words={result['top_words']}")
