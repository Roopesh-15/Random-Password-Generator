import random
import string
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


def generate_password():
    try:
        length = int(length_var.get())
        if length <= 0:
            messagebox.showerror("Error", "Password length must be greater than 0.")
            return
        
        characters = ""
        if letters_var.get():
            characters += string.ascii_letters
        if numbers_var.get():
            characters += string.digits
        if symbols_var.get():
            characters += string.punctuation
        
        if not characters:
            messagebox.showerror("Error", "Select at least one character type.")
            return
        
        password = "".join(random.choice(characters) for _ in range(length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for length.")

def copy_to_clipboard():
    password = password_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy!")

root = tk.Tk()
root.title("Advanced Password Generator")
root.geometry("400x350")
root.resizable(False, False)

title_label = tk.Label(root, text="Advanced Password Generator", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

length_frame = tk.Frame(root)
length_frame.pack(pady=5)
tk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT, padx=5)
length_var = tk.StringVar(value="12")
length_entry = tk.Entry(length_frame, textvariable=length_var, width=5)
length_entry.pack(side=tk.LEFT)

options_frame = tk.LabelFrame(root, text="Include Characters")
options_frame.pack(pady=10, padx=10, fill="x")

letters_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

tk.Checkbutton(options_frame, text="Letters (A-Z, a-z)", variable=letters_var).pack(anchor="w")
tk.Checkbutton(options_frame, text="Numbers (0-9)", variable=numbers_var).pack(anchor="w")
tk.Checkbutton(options_frame, text="Symbols (!@#$)", variable=symbols_var).pack(anchor="w")

generate_btn = tk.Button(root, text="Generate Password", command=generate_password, bg="#4CAF50", fg="white")
generate_btn.pack(pady=10, ipadx=10, ipady=5)

password_entry = tk.Entry(root, font=("Helvetica", 12), justify="center", width=30)
password_entry.pack(pady=5)

copy_btn = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, bg="#2196F3", fg="white")
copy_btn.pack(pady=5, ipadx=10, ipady=5)

footer_label = tk.Label(root, text="Created using Python", font=("Helvetica", 9))
footer_label.pack(side="bottom", pady=5)

root.mainloop()