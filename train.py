import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
from scipy.sparse import hstack
import matplotlib.pyplot as plt
import re
from colorama import Fore
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier
import math
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
from sklearn import metrics
import seaborn as sb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, mean_squared_error, precision_score, recall_score, f1_score, confusion_matrix
import seaborn as sns
from joblib import dump
import os

current_directory = os.path.dirname(__file__)

# Define relative paths
file_name = 'data.csv'
model_name = 'trained_model_RandomForest.joblib'

# Construct absolute paths
file_path = os.path.join(current_directory, file_name)
model_save_path = os.path.join(current_directory, model_name)

df = pd.read_csv(file_path)

# Function to check if a URL uses an IP address
def uses_ip_address(url):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return bool(ip_pattern.match(url))
    
def lengthurl(url):
    return len(url)

def countletters(url):
    count = 0
    for char in url:
        if char.isalpha():
            count += 1
    return count
    
def count_digits(url):
    count = 0
    for char in url:
        if char.isdigit():
            count += 1
    return count

def numberDots(url):
    count =0
    for char in url:
        if char=='.':
            count+=1

    return count

def numberHyphen(url):
    count =0
    for char in url:
        if char=='-':
            count+=1

    return count

def numberBackSlash(url):
    count =0
    for char in url:
        if char=='/':
            count+=1

    return count

def count_letter_digit_letter(url):
    pattern = re.compile(r'[a-zA-Z]\d+[a-zA-Z]')
    occurrences = len(re.findall(pattern, url))
    return occurrences


def count_digit_letter_digit(url):
    pattern = re.compile(r'\d+[a-zA-Z]\d+')
    occurrences = len(re.findall(pattern, url))
    return occurrences

# Function to count delimiters and find the longest word length
def analyze_delimiters_and_longest_word(url):
    delimiters_count = {}
    longest_word_length = 0
    
    # Define delimiters as any non-alphanumeric characters
    delimiters = re.compile(r'[^a-zA-Z0-9]+')
    components = re.split(delimiters, url)
    
    # Iterate over the components
    for component in components:
        # Count delimiters in each component
        delimiters_count[component] = len(re.findall(delimiters, component))
        
        # Find the longest word length
        if len(component) > longest_word_length:
            longest_word_length = len(component)
    
    return delimiters_count, longest_word_length

def check_domain_reputation(domain):
    known_malicious_domains = ['maliciousdomain1.com', 'maliciousdomain2.net']  # need to add more
    if domain in known_malicious_domains:
        return True
    else:
        return False
        

def has_suspicious_keywords(url):
    suspicious_keywords = ['phishing', 'malware', 'scam','faboleena','g0ogle']  # Add more 
    for keyword in suspicious_keywords:
        if keyword in url:
            return True
    return False
    
def has_subdomains(url):
    if len(url.split('.')) > 2:
        return 1
    else:
        return 0
    

def httpSecure(url):
    htp = urlparse(url).scheme
    match = str(htp)
    if match=='https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def number_rate(url):
    # Count occurrences of digits
    digit_count = sum(1 for char in url if char.isdigit())
    
    # Compute number rate
    rate = digit_count / len(url) if len(url) > 0 else 0
    
    return rate

def alphabet_entropy(url):
    # Count occurrences of each letter
    letter_counts = {chr(i): 0 for i in range(ord('a'), ord('z') + 1)}
    total_letters = 0
    
    for char in url.lower():
        if 'a' <= char <= 'z':  # Check if char is a lowercase English letter
            letter_counts[char] += 1
            total_letters += 1
    
    # Compute probabilities and entropy
    entropy = 0
    for count in letter_counts.values():
        if count > 0:
            probability = count / total_letters
            entropy -= probability * math.log2(probability)
    
    return entropy
def starts_with_https(url):
    return url.startswith("https://")

def get_accuracy(name, trained_model, x_train, y_train, x_test, y_test):
    tree_predict = trained_model.predict(x_test)
    print("Testing accuracy   :", metrics.accuracy_score(y_test, tree_predict) * 100, "%")
    print("MSE [TEST]          :", mean_squared_error(y_test, tree_predict))
    tree_predict1 = trained_model.predict(x_train)
    print("Training accuracy  :", metrics.accuracy_score(y_train, tree_predict1) * 100, "%")
    print("MSE [TRAIN]         :",mean_squared_error(y_train, tree_predict1))

    print("precision : ",precision_score(y_test, tree_predict,average='micro'))
    print("recall    : ",recall_score(y_test, tree_predict,average='micro'))
    print("f1_score  : ",f1_score(y_test, tree_predict,average='micro'))
    cf1 = confusion_matrix(y_test,tree_predict)
    sb.heatmap(cf1,annot=True,fmt = '.0f')
    plt.xlabel('prediction')
    plt.ylabel('Actual')
    plt.title(name+ ' Confusion Matrix')
    plt.show()
    print(classification_report(y_train,  trained_model.predict(x_train)))
    print(classification_report(y_test,  trained_model.predict(x_test)))


sw=list(set(stopwords.words("english")))
df['clean_url']=df.url.astype(str)
#df['clean_url']=df['clean_url'].apply(lambda x:" ".join([word for word in x.split() if word not in sw]))
tok= RegexpTokenizer(r'[A-Za-z0-9]+')
tok.tokenize(df.url[1])
df.clean_url=df.clean_url.map(lambda x: tok.tokenize(x))
#nltk.download('omw-1.4')
wnl = WordNetLemmatizer()
df['lem_url'] = df['clean_url'].map(lambda x: [wnl.lemmatize(word) for word in x])
word_vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=1500)
tfidf_features = word_vectorizer.fit_transform(df['lem_url'].astype(str))

# Initialize CountVectorizer
cv = CountVectorizer()
count_features = cv.fit_transform(df['lem_url'].astype(str))


def main():
    df['uses_ip'] = df['url'].apply(uses_ip_address)
    df['count_digits'] = df['url'].apply(count_digits)
    df['count_letters'] = df['url'].apply(countletters)
    df['length'] = df['url'].apply(lengthurl)
    df['letter_digit_letter_count'] = df['url'].apply(count_letter_digit_letter)
    df['digit_letter_digit_count'] = df['url'].apply(count_digit_letter_digit)
    df['has_suspicious_keywords'] = df['url'].apply(has_suspicious_keywords)
    df['has_subdomains'] = df['url'].apply(has_subdomains)
    df['numberDots'] = df['url'].apply(numberDots) 
    df['numberHyphen'] = df['url'].apply(numberHyphen) 
    df['numberBackSlash'] = df['url'].apply(numberBackSlash) 
    df['number_rate'] = df['url'].apply(number_rate)
    df['alphabet_entropy'] = df['url'].apply(alphabet_entropy)
    df['starts_with_https'] = df['url'].apply(starts_with_https)
    
    
    print(stopwords.words('english'))

    # Split features and target variable
    y = df['result']
    X = df.drop(columns=['url', 'label', 'result'])
    numerical_features = df[['uses_ip', 'count_digits', 'count_letters', 'length', 'letter_digit_letter_count', 
                             'digit_letter_digit_count', 'has_suspicious_keywords', 'has_subdomains', 'numberDots', 
                             'numberHyphen', 'numberBackSlash', 'number_rate', 'alphabet_entropy','starts_with_https']]

    # Concatenate features
    X = hstack([numerical_features.astype(float), tfidf_features, count_features])
    x_train, x_test, y_train, y_test = train_test_split(X, y, random_state=42, test_size=0.3, shuffle=True)
    
    # Train Logistic Regression model
    trained_clf_RandomForest = RandomForestClassifier().fit(x_train, y_train)

    #get_accuracy('LogisticRegression', trained_clf_LogisticRegression, x_train, y_train, x_test, y_test)
        # Evaluate the trained model
    print("Random Forest Classifier Metrics:")
    print("Training accuracy: {:.2f}%".format(accuracy_score(y_train, trained_clf_RandomForest.predict(x_train)) * 100))
    print("Testing accuracy: {:.2f}%".format(accuracy_score(y_test, trained_clf_RandomForest.predict(x_test)) * 100))
    print("Precision: {:.2f}".format(precision_score(y_test, trained_clf_RandomForest.predict(x_test), average='weighted')))
    print("Recall: {:.2f}".format(recall_score(y_test, trained_clf_RandomForest.predict(x_test), average='weighted')))
    print("F1 Score: {:.2f}".format(f1_score(y_test, trained_clf_RandomForest.predict(x_test), average='weighted')))
    '''
    # Confusion matrix visualization
    cf_matrix = confusion_matrix(y_test, trained_clf_RandomForest.predict(x_test))
    sns.heatmap(cf_matrix, annot=True, fmt='d', cmap='Blues', xticklabels=['Non-Malicious', 'Malicious'], yticklabels=['Non-Malicious', 'Malicious'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Random Forest Classifier Confusion Matrix')
    plt.show()
    '''
    
    dump(trained_clf_RandomForest, model_save_path) 
    print("its over")
    return 
if __name__ == "__main__":
    main()
