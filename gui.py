from tkinter import Tk, Entry, Button, messagebox, Label, Canvas
from PIL import Image, ImageTk
import requests
import os

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


def resize_bg_image(event):
    """
    Resize the background image to match the window size.
    
    Parameters:
        event (Event): The resizing event.
    """
    global bg_image_resized
    global bg_image_tk  # Declare global variable for bg_image_tk
    global canvas  # Declare global variable for canvas
    # Resize the background image
    bg_image_resized = bg_image.resize((event.width, event.height), Image.LANCZOS)
    bg_image_tk = ImageTk.PhotoImage(bg_image_resized)
    canvas.config(width=event.width, height=event.height)  # Update canvas size
    canvas.create_image(0, 0, anchor="nw", image=bg_image_tk)


root = Tk()
root.title("URL Classifier")

# Set initial size of the window
root.geometry("512x256")

# Load the background image
script_dir = os.path.dirname(os.path.abspath(__file__))
bg_image = Image.open(os.path.join(script_dir, 'img.png'))
bg_image_resized = bg_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.LANCZOS)
bg_image_tk = ImageTk.PhotoImage(bg_image_resized)

# Create a Canvas widget to display the background image
canvas = Canvas(root, width=root.winfo_screenwidth(), height=root.winfo_screenheight())
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=bg_image_tk)

# Bind the resize function to the window resizing event
root.bind('<Configure>', resize_bg_image)

# Create GUI components (Label, Entry, Button)
Label(root, text="Enter URL:", bg='white').place(x=50, y=50)
url_entry = Entry(root, width=50)
url_entry.place(x=150, y=50)
classify_button = Button(root, text="Classify", command=classify_url)
classify_button.place(x=230, y=100)
result_label = Label(root, text="")
result_label.place(x=50, y=100)

root.mainloop()
