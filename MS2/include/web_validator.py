import tkinter as tk
from tkinter import messagebox
import re
from bs4 import BeautifulSoup

class WebValidator:
    def __init__(self, parent):
        self.frame = tk.Frame(parent)  # Create a frame inside the notebook tab

        tk.Label(self.frame, text="Name:").grid(row=0, column=0)
        self.name_entry = tk.Entry(self.frame)
        self.name_entry.grid(row=0, column=1)

        tk.Label(self.frame, text="Email:").grid(row=1, column=0)
        self.email_entry = tk.Entry(self.frame)
        self.email_entry.grid(row=1, column=1)

        tk.Label(self.frame, text="Age:").grid(row=2, column=0)
        self.age_entry = tk.Entry(self.frame)
        self.age_entry.grid(row=2, column=1)

        tk.Label(self.frame, text="Message:").grid(row=3, column=0)
        self.message_entry = tk.Text(self.frame, height=4, width=30)
        self.message_entry.grid(row=3, column=1)

        tk.Button(self.frame, text="Submit", command=self.submit_form).grid(row=4, column=1)

    def validate_form(self):
        errors = {}
        sanitized_data = {}

        # Validate Name (Required)
        name = self.name_entry.get().strip()
        if not name:
            errors["name"] = "Name is required."
        else:
            sanitized_data["name"] = name

        # Validate Email (Required & Valid Format)
        email = self.email_entry.get().strip()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not email:
            errors["email"] = "Email is required."
        elif not re.match(email_pattern, email):
            errors["email"] = "Invalid email format."
        else:
            sanitized_data["email"] = email

        # Validate Age (Optional, but must be between 18-120 if provided)
        age = self.age_entry.get().strip()
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
        message = self.message_entry.get("1.0", tk.END).strip()
        soup = BeautifulSoup(message, "html.parser")
        sanitized_data["message"] = soup.get_text().strip()

        return errors, sanitized_data

    def submit_form(self):
        errors, sanitized_data = self.validate_form()
        if errors:
            messagebox.showerror("Form Errors", str(errors))
        else:
            messagebox.showinfo("Success", "Form submitted successfully!")
