import nltk
nltk.download("stopwords")
import pandas as pd

# Load dataset
data = pd.read_csv("../data/fake_job_postings.csv")

# Print total shape
print("Dataset Shape:", data.shape)

# Print class distribution
print("\nFraudulent value counts:")
print(data["fraudulent"].value_counts())
print("\nColumns:")
print(data.columns)
# Select important text columns
text_columns = ["title", "company_profile", "description", "requirements", "benefits"]

# Fill missing values with empty string
data[text_columns] = data[text_columns].fillna("")

# Combine all text into single column
data["combined_text"] = (
    data["title"] + " " +
    data["company_profile"] + " " +
    data["description"] + " " +
    data["requirements"] + " " +
    data["benefits"]
)

print("\nCombined text sample:")
print(data["combined_text"].head())
import re
from nltk.corpus import stopwords

stop_words = set(stopwords.words("english"))

def clean_text(text):
    # Convert to lowercase
    text = text.lower()
    
    # Remove special characters and numbers
    text = re.sub(r"[^a-zA-Z]", " ", text)
    
    # Remove extra spaces
    text = re.sub(r"\s+", " ", text)
    
    # Remove stopwords
    words = text.split()
    words = [word for word in words if word not in stop_words]
    
    return " ".join(words)
print("\nCleaning text...")

data["cleaned_text"] = data["combined_text"].apply(clean_text)

print("\nCleaned text sample:")
print(data["cleaned_text"].head())
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
print("\nApplying TF-IDF...")

tfidf = TfidfVectorizer(max_features=5000)

X = tfidf.fit_transform(data["cleaned_text"])

y = data["fraudulent"]

print("TF-IDF Shape:", X.shape)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTrain size:", X_train.shape)
print("Test size:", X_test.shape)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
print("\nTraining Logistic Regression...")

model = LogisticRegression(max_iter=1000, class_weight="balanced")

model.fit(X_train, y_train)

print("Model training complete.")
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
import pickle
import os

# Create model directory if not exists
os.makedirs("../model", exist_ok=True)

# Save trained model
with open("../model/scam_model.pkl", "wb") as f:
    pickle.dump(model, f)

# Save TF-IDF vectorizer
with open("../model/tfidf_vectorizer.pkl", "wb") as f:
    pickle.dump(tfidf, f)

print("\nModel and vectorizer saved successfully!")