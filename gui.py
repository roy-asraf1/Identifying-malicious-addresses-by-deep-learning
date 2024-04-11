from tkinter import Tk, Label, Entry, Button, messagebox
import requests

def classify_url():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return

    try:
        response = requests.post('http://localhost:5000/classify', json={'url': url})
        if response.status_code == 200:
            result = response.json().get('classification')
            result_label.config(text=f"Classification: {result}")
        else:
            messagebox.showerror("Error", "Failed to classify URL.")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Error: {str(e)}")

root = Tk()
root.title("URL Classifier")

# Create GUI components (Label, Entry, Button)
Label(root, text="Enter URL:").grid(row=0, column=0)
url_entry = Entry(root, width=50)
url_entry.grid(row=0, column=1)
classify_button = Button(root, text="Classify", command=classify_url)
classify_button.grid(row=1, column=0, columnspan=2)
result_label = Label(root, text="")
result_label.grid(row=2, column=0, columnspan=2)

root.mainloop()