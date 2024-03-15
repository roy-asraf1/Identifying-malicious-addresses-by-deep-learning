import train
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from scipy.sparse import hstack
import numpy as np
import pandas as pd
import re
import nltk
from nltk.tokenize import RegexpTokenizer
from nltk.stem import WordNetLemmatizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, mean_squared_error, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from urllib.parse import urlparse

# Function definitions for feature extraction
# Your feature extraction functions go here

# Function to predict using the trained model
def predict_url(url, trained_model, vectorizer):
    # Preprocess the URL
    tokenizer = RegexpTokenizer(r'[A-Za-z0-9]+')
    clean_url = tokenizer.tokenize(url)
    lemmatizer = WordNetLemmatizer()
    lem_url = [lemmatizer.lemmatize(word) for word in clean_url]
    
    # Transform the URL using the vectorizer
    feature = vectorizer.transform([' '.join(lem_url)])
    
    # Predict using the trained model
    prediction = trained_model.predict(feature)
    return prediction[0]

# Function to train the model
def train_model():
    # Load the dataset
    file_path = '/home/roy/Documents/last year/cyber/phishing_site_urls.csv'
    df = pd.read_csv(file_path)
    df['Label'] = df['Label'].replace({'good': 1, 'bad': 0})
    

    trained_clf = RandomForestClassifier(n_estimators=100, random_state=42)
    trained_clf.fit(train.getxtrain(), train.getytrain())
    
    # Return the trained model and vectorizer
    return trained_clf, vectorizer

# Function to handle button click for checking URL
def check_url():
    url = url_entry.get()
    prediction = predict_url(url, trained_model, vectorizer)
    if prediction == 1:
        result_label.config(text="Good URL")
    else:
        result_label.config(text="Bad URL")

# Create the main window
root = tk.Tk()
root.title("URL Checker")

# Create and pack widgets
url_label = tk.Label(root, text="Enter URL:")
url_label.pack()

url_entry = tk.Entry(root, width=50)
url_entry.pack()

check_button = tk.Button(root, text="Check URL", command=check_url)
check_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

# Train the model
trained_model, vectorizer = train_model()

# Start the GUI event loop
root.mainloop()


