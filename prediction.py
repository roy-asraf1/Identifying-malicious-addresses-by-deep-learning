from PIL import Image, ImageTk
from joblib import load
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from scipy.sparse import hstack
import joblib
import train
import numpy as np
import os

# Get the full path to the current script file
script_path = os.path.abspath(__file__)

# Get the directory of the current script file
script_dir = os.path.dirname(script_path)

# Load the pre-trained model
loaded_model = joblib.load(os.path.join(script_dir, 'trained_model_RandomForest.joblib'))


def predict_url(url):
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
    numerical_features = np.array([[uses_ip, count_digits_val, count_letters_val, length_val, letter_digit_letter_count_val, 
                                     digit_letter_digit_count_val, has_suspicious_keywords_val, has_subdomains_val, numberDots_val, 
                                     numberHyphen_val, numberBackSlash_val, number_rate_val, alphabet_entropy_val, starts_with_https_val]])

    # Concatenate features
    X = hstack([numerical_features.astype(float), tfidf_features, count_features])

    # Predict using the loaded model
    prediction = loaded_model.predict(X)

    return prediction[0]

def classify_url():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return

    # Check if the URL starts with 'http://' or 'https://'
    if not url.startswith('http://') and not url.startswith('https://'):
        # Try both 'http://' and 'https://' prefixes
        http_url = 'http://' + url
        https_url = 'https://' + url

        # Process and predict for both URLs
        http_prediction = predict_url(http_url)
        https_prediction = predict_url(https_url)
        
        if http_prediction == https_prediction:
            update_result_and_button(http_prediction)
        else:
            update_result_and_button(http_prediction)

    else:
        # Process and predict for the given URL
        prediction = predict_url(url)
        
        # Update the result label only
        result_label.config(text=f"Classification: {prediction}")


def update_result_and_button(prediction):
    # Update the result label
    # Update the button style based on the prediction
    if prediction == 0:
        result_label.config(text=f"Classification: Benign", background='light green', foreground='black')
        classify_button.configure(style='GreenButton.TButton')
        url_entry.configure(foreground='dark green')
    else:
        result_label.config(text=f"Classification: Malicious", background='light coral', foreground='black')
        classify_button.configure(style='RedButton.TButton')
        url_entry.configure(foreground='red')


def reset_url_entry_color(*args):
    url_entry.configure(foreground='black')


def resize_bg_image(event):
    global bg_image_resized
    global bg_image_tk  # Declare global variable for bg_image_tk
    global canvas  # Declare global variable for canvas
    # Resize the background image to match the size of the window
    bg_image_resized = bg_image_open.resize((event.width, event.height), Image.LANCZOS)
    bg_image_tk = ImageTk.PhotoImage(bg_image_resized)
    canvas.config(width=event.width, height=event.height)  # Update canvas size
    canvas.create_image(0, 0, anchor="nw", image=bg_image_tk)


# GUI setup
root = tk.Tk()
root.title("URL Classifier")

# Set initial size of the window
root.geometry("512x256")  

# Load the background image
bg_image_open = Image.open(os.path.join(script_dir, 'img.png'))
# Resize the background image to match the initial size of the window
bg_image_resized = bg_image_open.resize((root.winfo_width(), root.winfo_height()), Image.LANCZOS)
bg_image_tk = ImageTk.PhotoImage(bg_image_resized)

# Create a canvas and place the image on it
canvas = tk.Canvas(root)
canvas.place(x=0, y=0, relwidth=1, relheight=1)

# Bind the resize function to the window resizing event
root.bind('<Configure>', resize_bg_image)

# URL Entry
url_label = ttk.Label(root, text="Enter URL:", foreground="white", background="black")
url_label.place(x=20, y=20)
url_entry = ttk.Entry(root, width=50, style='Default.TEntry')
url_entry.place(x=100, y=20)

# Classify Button
classify_button = ttk.Button(root, text="Classify", command=classify_url, style ='Default.TButton', width=10)
classify_button.place(x=200, y=50)

# Result Label
result_label = ttk.Label(root, text="")
result_label.place(x=20, y=80)

# Define custom button styles
root.style = ttk.Style(root)
root.style.configure('GreenButton.TButton', background='green')
root.style.configure('RedButton.TButton', background='red')

# Define custom entry styles
root.style.configure('Green.TEntry', background='light green')
root.style.configure('Red.TEntry', background='light coral')

url_entry.bind("<KeyRelease>", reset_url_entry_color)

root.mainloop()
