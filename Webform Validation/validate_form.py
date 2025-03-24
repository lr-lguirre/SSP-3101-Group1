from flask import Flask, request, jsonify, render_template
import re
from html import escape
from bs4 import BeautifulSoup
import scrapy
import tkinter as tk
from tkinter import messagebox

import threading  # For running Flask in a separate thread

ENABLE_TKINTER = True  # Set to True to enable Tkinter

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def home():
    return render_template("index.html")

def validate_form(form_data):
    errors = {}
    sanitized_data = {}

    # Validate Name (Required)
    if not form_data.get("name"):
        errors["name"] = "Name is required."
    else:
        sanitized_data["name"] = form_data["name"].strip()

    # Validate Email (Required & Valid Format)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not form_data.get("email"):
        errors["email"] = "Email is required."
    elif not re.match(email_pattern, form_data["email"]):
        errors["email"] = "Invalid email format."
    else:
        sanitized_data["email"] = form_data["email"].strip()

    # Validate Age (Optional, but must be between 18-120 if provided)
    age = form_data.get("age")
    if age:
        try:
            age = int(age)
            if age < 18 or age > 120:
                errors["age"] = "Age must be between 18 and 120."
            else:
                sanitized_data["age"] = age
        except ValueError:
            errors["age"] = "Age must be a valid integer."

    # Sanitize Message (Optional, remove HTML/script tags using BeautifulSoup)
    message = form_data.get("message", "")
    soup = BeautifulSoup(message, "html.parser")
    sanitized_data["message"] = soup.get_text().strip()

    return {"errors": errors, "sanitized_data": sanitized_data}

@app.route('/submit', methods=['POST'])
def submit_form():
    form_data = request.json
    result = validate_form(form_data)
    return jsonify(result)

# Tkinter GUI Setup (Disabled by Default)
def submit_tk_form():
    form_data = {
        "name": name_entry.get(),
        "email": email_entry.get(),
        "age": age_entry.get(),
        "message": message_entry.get("1.0", tk.END)
    }

    result = validate_form(form_data)
    if result["errors"]:
        messagebox.showerror("Form Errors", str(result["errors"]))
    else:
        messagebox.showinfo("Success", "Form submitted successfully!")

if ENABLE_TKINTER:
    root = tk.Tk()
    root.title("Form Validation")

    tk.Label(root, text="Name:").grid(row=0, column=0)
    name_entry = tk.Entry(root)
    name_entry.grid(row=0, column=1)

    tk.Label(root, text="Email:").grid(row=1, column=0)
    email_entry = tk.Entry(root)
    email_entry.grid(row=1, column=1)

    tk.Label(root, text="Age:").grid(row=2, column=0)
    age_entry = tk.Entry(root)
    age_entry.grid(row=2, column=1)

    tk.Label(root, text="Message:").grid(row=3, column=0)
    message_entry = tk.Text(root, height=4, width=30)
    message_entry.grid(row=3, column=1)

    tk.Button(root, text="Submit", command=submit_tk_form).grid(row=4, column=1)

if __name__ == '__main__':
    if ENABLE_TKINTER:
        root.mainloop()  # Only runs if Tkinter is enabled
    else:
        app.run(debug=True)  # Flask always runs if Tkinter is disabled
