import sys
import logging
from flask import Flask, request, jsonify
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from scipy.sparse import hstack
import joblib
import train
import numpy as np
import os

app = Flask(__name__)

# Configure Flask logging to use stdout
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)

# Load the pre-trained model
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
loaded_model = joblib.load(os.path.join(script_dir, 'trained_model_RandomForest.joblib'))

@app.route('/classify', methods=['POST'])
def classify_url():
    # Get URL from request
    url = request.json.get('url')

    app.logger.info("Received URL: %s", url)
    # if url == "www.google.com":
    #     return jsonify({'classification': 'Benign'})

    if not url:
        return jsonify({'error': 'URL not provided'}), 400

    # Check if the URL starts with 'http://' or 'https://'
    if not url.startswith('http://') and not url.startswith('https://'):
        # Try both 'http://' and 'https://' prefixes
        http_url = 'http://' + url
        https_url = 'https://' + url

        # Process and predict for both URLs
        http_prediction = predict_url(http_url)
        https_prediction = predict_url(https_url)
        app.logger.info("HTTP Prediction: %s", http_prediction)
        app.logger.info("HTTPS Prediction: %s", https_prediction)

        is_malicious = http_prediction == 1 or https_prediction == 1

        return jsonify({'classification': 'Malicious' if is_malicious else 'Benign'})
    
    else:
        # Remove 'http://' or 'https://' prefixes if present
        if url.startswith('http://'):
            url = url[len('http://'):]
        elif url.startswith('https://'):
            url = url[len('https://'):]

        http_url = 'http://' + url
        https_url = 'https://' + url

        # Process and predict for both URLs
        http_prediction = predict_url(http_url)
        https_prediction = predict_url(https_url)
        app.logger.info("HTTP Prediction: %s", http_prediction)
        app.logger.info("HTTPS Prediction: %s", https_prediction)

        is_malicious = http_prediction == 1 or https_prediction == 1
    
        return jsonify({'classification': 'Malicious' if is_malicious else 'Benign'})

def predict_url(url):
    """
    Predict the class (Benign/Malicious) of a given URL.
    
    Parameters:
        url (str): The URL to predict.
    
    Returns:
        int: Predicted class label (0 for Benign, 1 for Malicious).
    """
    # Extract features from the URL
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

    # Tokenize and lemmatize the URL
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
    numerical_features = np.array([[uses_ip, count_digits_val, count_letters_val, length_val, letter_digit_letter_count_val,
                                     digit_letter_digit_count_val, has_suspicious_keywords_val, has_subdomains_val, numberDots_val,
                                     numberHyphen_val, numberBackSlash_val, number_rate_val, alphabet_entropy_val, starts_with_https_val]])

    # Concatenate features
    X = hstack([numerical_features.astype(float), tfidf_features, count_features])

    # Predict using the loaded model
    prediction = loaded_model.predict(X)

    return prediction[0]


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # Run the Flask app in debug mode for development
