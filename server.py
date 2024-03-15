#configuration
import os
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import numpy as np # linear algebra
import matplotlib.pyplot as plt
from matplotlib import style 
from scipy.sparse import hstack
import seaborn as sns
from textwrap import wrap
import matplotlib.pyplot as plt
import re
import matplotlib.pyplot as plt
from colorama import Fore
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, ExtraTreesClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
import math
from urllib.parse import urlparse
import nltk
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer  
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse
from nltk.corpus import stopwords
from nltk.tokenize import RegexpTokenizer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn import metrics
from sklearn.metrics import mean_squared_error
from sklearn.metrics import precision_score,recall_score,f1_score
import seaborn as sb
from collections import Counter
from textwrap import wrap
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, mean_squared_error, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
import seaborn as sns
import matplotlib.pyplot as plt
import nltk
import pandas as pd


file_path = '/home/roy/Documents/last year/cyber/phishing_site_urls.csv'
df = pd.read_csv(file_path)
df['Label'] = df['Label'].replace({'good': 1, 'bad': 0}) #for more complex work


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
    suspicious_keywords = ['phishing', 'malware', 'scam']  # Add more 
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
# Function to check if the domain name is an IP address
def uses_ip_address(url):
    domain = urlparse(url).hostname
    if domain:
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        return bool(ip_pattern.match(domain))
    return False

# Function to check if the port number is the default HTTP port (80)
def uses_default_port(url):
    parsed_url = urlparse(url)
    port = parsed_url.port
    if not port:  # If port is not specified in the URL
        return True  # Default to port 80
    return port == 80  # Compare port to default HTTP port



df['uses_ip'] = df['URL'].apply(uses_ip_address)
df['count_digits'] = df['URL'].apply(count_digits)
df['count_letters'] = df['URL'].apply(countletters)
df['length'] = df['URL'].apply(lengthurl)
df['letter_digit_letter_count'] = df['URL'].apply(count_letter_digit_letter)
df['digit_letter_digit_count'] = df['URL'].apply(count_digit_letter_digit)
df['delimiters_count'], df['longest_word_length'] = zip(*df['URL'].apply(analyze_delimiters_and_longest_word))
df['has_suspicious_keywords'] = df['URL'].apply(has_suspicious_keywords)
df['has_subdomains'] = df['URL'].apply(has_subdomains)
df['numberDots'] = df['URL'].apply(numberDots) 
df['numberHyphen'] = df['URL'].apply(numberHyphen) 
df['numberBackSlash'] = df['URL'].apply(numberBackSlash) 
df['number_rate'] = df['URL'].apply(number_rate)
df['alphabet_entropy'] = df['URL'].apply(alphabet_entropy)
df['uses_ip_address'] = df['URL'].apply(uses_ip_address)
df['uses_default_port'] = df['URL'].apply(uses_default_port)

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

print(stopwords.words('english'))
sw=list(set(stopwords.words("english")))
df['clean_url']=df.URL.astype(str)
tok= RegexpTokenizer(r'[A-Za-z0-9]+')
tok.tokenize(df.URL[1])
df.clean_url=df.clean_url.map(lambda x: tok.tokenize(x))
nltk.download('omw-1.4')
wnl = WordNetLemmatizer()
df['lem_url'] = df['clean_url'].map(lambda x: [wnl.lemmatize(word) for word in x])
word_vectorizer = TfidfVectorizer(ngram_range=(1,1), max_features =1500)
unigramdataGet= word_vectorizer.fit_transform(df['lem_url'].astype('str'))
unigramdataGet = unigramdataGet.toarray()
vocab = word_vectorizer.get_feature_names_out ()
x=pd.DataFrame(np.round(unigramdataGet, 1), columns=vocab)
x[x>0] = 1
cv = CountVectorizer()
feature = cv.fit_transform(df.lem_url.astype('str')) 
x = hstack((feature, df['uses_ip'].values.reshape(-1, 1)))
y=df.Label
x_train,x_test,y_train,y_test =  train_test_split(x,y,random_state=42,test_size=0.2,shuffle=True)
trained_clf_RandomForest = RandomForestClassifier(n_estimators=100, random_state=42)
trained_clf_RandomForest.fit(x_train, y_train)
get_accuracy('RandomForest', trained_clf_RandomForest, x_train, y_train, x_test, y_test)


def getxtrain():
    return x_train
def getytrain():
    return y_train
