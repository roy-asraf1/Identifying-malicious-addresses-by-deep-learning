
from joblib import load
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from scipy.sparse import hstack
import joblib
import train

# Load the pre-trained model
loaded_model = joblib.load('your_model_file_path.pkl')

def classify_url():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return
    
    uses_ip = train.uses_ip_address(url)
    count_digits_val = train.count_digits(url)
    count_letters_val = train.countletters(url)
    length_val = train.lengthurl(url)
    letter_digit_letter_count_val = train.count_letter_digit_letter(url)
    digit_letter_digit_count_val = train.count_digit_letter_digit(url)
    has_suspicious_keywords_val = train.has_suspicious_keywords(url)
    has_subdomains_val = train.has_subdomains(url)
    numberDots_val = train.numberDots(url)
    numberHyphen_val = train.numberHyphen(url)
    numberBackSlash_val = train.numberBackSlash(url)
    number_rate_val = train.number_rate(url)
    alphabet_entropy_val = train.alphabet_entropy(url)
    starts_with_https_val = train.starts_with_https(url)

    # Tokenize and lemmatize
    clean_url = url
    tok = train.RegexpTokenizer(r'[A-Za-z0-9]+')
    clean_url = tok.tokenize(clean_url)
    wnl = train.WordNetLemmatizer()
    lem_url = [wnl.lemmatize(word) for word in clean_url]

    # TF-IDF Vectorization
    tfidf_features = train.word_vectorizer.transform([str(lem_url)])

    # Count Vectorization
    count_features = train.cv.transform([str(lem_url)])

    # Numerical features
    numerical_features = train.np.array([[uses_ip, count_digits_val, count_letters_val, length_val, letter_digit_letter_count_val, 
                                     digit_letter_digit_count_val, has_suspicious_keywords_val, has_subdomains_val, numberDots_val, 
                                     numberHyphen_val, numberBackSlash_val, number_rate_val, alphabet_entropy_val, starts_with_https_val]])

    # Concatenate features
    X = hstack([numerical_features.astype(float), tfidf_features, count_features])

    # Predict using the loaded model
    prediction = loaded_model.predict(X)
    
    # Display result
    result_label.config(text=f"Classification: {prediction[0]}")

# GUI setup
root = tk.Tk()
root.title("URL Classifier")

# URL Entry
url_label = ttk.Label(root, text="Enter URL:")
url_label.pack(pady=5)
url_entry = ttk.Entry(root, width=50)
url_entry.pack(pady=5)

# Classify Button
classify_button = ttk.Button(root, text="Classify", command=classify_url)
classify_button.pack(pady=5)

# Result Label
result_label = ttk.Label(root, text="")
result_label.pack(pady=5)

root.mainloop()
