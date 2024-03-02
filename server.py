
import re
import math
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, log_loss
from sklearn.impute import SimpleImputer
import matplotlib.pyplot as plt
from urllib.parse import urlparse
#import tkinter as tk
import socket
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
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
    count = 0
    for char in url:
        if char == '.':
            count += 1

    return count


def numberHyphen(url):
    count = 0
    for char in url:
        if char == '-':
            count += 1

    return count


def numberBackSlash(url):
    count = 0
    for char in url:
        if char == '/':
            count += 1

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

'''
def analyze_whois(domain):
    try:
        domain_info = whois.whois(domain)
        # You would analyze the WHOIS information here and return True/False based on some criteria
        # For simplicity, let's just return True if we get WHOIS information without errors
        return 1
    except:
        return 0
    '''

def httpSecure(url):
    htp = urlparse(url).scheme
    match = str(htp)
    if match == 'https':
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

    # Define the urlparsee function
def urlparsee(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Split domain into its components
    domain_components = domain.split('.')

    # Encode each component into a one-hot vector
    domain_vector = []
    for component in domain_components:
        if component.isdigit():
            domain_vector.append(int(component))  # If the component is a number, simply append it
        else:
            for char in component:
                domain_vector.append(ord(char))  # Convert characters to ASCII and append

    # Find the most common urlparse
    most_common_urlparse = max(set(domain_components), key=domain_components.count)

    return domain_vector, most_common_urlparse


file_path = '/home/roy/Documents/last year/cyber/data.csv'
df = pd.read_csv(file_path)
df.drop_duplicates(subset=['url'], keep='first', inplace=True)
df['https'] = df['url'].apply(lambda i: httpSecure(i))
df['uses_ip'] = df['url'].apply(uses_ip_address)
df['count_digits'] = df['url'].apply(count_digits)
df['count_letters'] = df['url'].apply(countletters)
df['length'] = df['url'].apply(lengthurl)
df['letter_digit_letter_count'] = df['url'].apply(count_letter_digit_letter)
df['digit_letter_digit_count'] = df['url'].apply(count_digit_letter_digit)
df['delimiters_count'], df['longest_word_length'] = zip(*df['url'].apply(analyze_delimiters_and_longest_word))
df['domain_reputation'] = df['url'].apply(check_domain_reputation)  #
df['has_suspicious_keywords'] = df['url'].apply(has_suspicious_keywords)
df['has_subdomains'] = df['url'].apply(has_subdomains)
# df['whois_info'] = df['url'].apply(analyze_whois)  #
df['numberDots'] = df['url'].apply(numberDots)
df['numberHyphen'] = df['url'].apply(numberHyphen)
df['numberBackSlash'] = df['url'].apply(numberBackSlash)
df['number_rate'] = df['url'].apply(number_rate)
df['alphabet_entropy'] = df['url'].apply(alphabet_entropy)
df['uses_ip_address'] = df['url'].apply(uses_ip_address)
df['uses_default_port'] = df['url'].apply(uses_default_port)





X = df[['uses_ip', 'count_letters', 'length', 'count_digits', 'number_rate', 'alphabet_entropy', 'uses_ip_address',
        'uses_default_port', 'longest_word_length',
        'letter_digit_letter_count', 'digit_letter_digit_count',
        'has_suspicious_keywords',
        'has_subdomains', 'numberDots', 'numberHyphen', 'numberBackSlash']]
y = df['label']

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Impute missing values
imputer = SimpleImputer(strategy='constant', fill_value=0)
X_train_imputed = imputer.fit_transform(X_train)
X_test_imputed = imputer.transform(X_test)

# Train the Random Forest Classifier model
model = RandomForestClassifier(random_state=42)
model.fit(X_train_imputed, y_train)

# Predict on the testing set
y_pred = model.predict(X_test_imputed)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

# Calculate log loss
train_loss = log_loss(y_train, model.predict_proba(X_train_imputed))
test_loss = log_loss(y_test, model.predict_proba(X_test_imputed))
print("Train Loss:", train_loss)
print("Test Loss:", test_loss)

# Generate classification report
class_report = classification_report(y_test, y_pred)
print("Classification Report:")
print(class_report)

# Generate class-wise metrics
class_report_df = pd.DataFrame(classification_report(y_test, y_pred, output_dict=True)).transpose()
print("Class-wise Metrics:")
print(class_report_df)

# Plot logistic loss
loss_values = [train_loss, test_loss]
labels = ['Training Loss', 'Testing Loss']

plt.figure(figsize=(8, 6))
plt.bar(labels, loss_values, color=['blue', 'orange'])
plt.title('Logistic Loss')
plt.ylabel('Loss')
plt.tight_layout()
plt.savefig('salary_distrybution.png')
plt.close()


if __name__ == "__main__":
    
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
                print("Received")


    window = tk.Tk()
    greeting = tk.Label(text="hello attacker", font=("Arial"))
    window.mainloop()
    '''
    #learning()