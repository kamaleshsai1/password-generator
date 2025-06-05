import tkinter as tk
from tkinter import messagebox, font
import random
import string

def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_special):
    """Generate a random password based on user criteria."""
    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character type must be selected.")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def on_generate():
    """Handle the password generation when the button is clicked."""
    try:
        length = int(length_entry.get())
        if length <= 0:
            raise ValueError("Password length must be a positive integer.")
        
        use_uppercase = uppercase_var.get()
        use_lowercase = lowercase_var.get()
        use_numbers = numbers_var.get()
        use_special = special_var.get()

        password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_special)
        password_entry.config(state='normal')
        password_entry.delete(0, tk.END)  # Clear previous password
        password_entry.insert(0, password)  # Insert new password
        password_entry.config(state='readonly')
    except ValueError as e:
        messagebox.showerror("Input Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Password Generator")

# Make full screen
root.attributes('-fullscreen', True)

# Root background color
bg_color = "#282c34"
fg_color = "#f0f0f0"
accent_color = "#61afef"
button_color = "#98c379"
error_color = "#e06c75"

root.configure(bg=bg_color)

# Set a modern font
default_font = font.nametofont("TkDefaultFont")
default_font.configure(size=14)

# Container frame
container = tk.Frame(root, bg=bg_color, padx=40, pady=40)
container.pack(expand=True)

# Title label
title_font = ("Segoe UI", 32, "bold")
title_label = tk.Label(container, text="Secure Password Generator", font=title_font, fg=accent_color, bg=bg_color)
title_label.grid(row=0, column=0, columnspan=2, pady=(0, 40), sticky='n')

# Password length label and entry
length_label = tk.Label(container, text="Password Length:", fg=fg_color, bg=bg_color, font=("Segoe UI", 18))
length_label.grid(row=1, column=0, sticky='w', pady=10, padx=(0,20))
length_entry = tk.Entry(container, font=("Segoe UI", 18), width=10, justify='center')
length_entry.grid(row=1, column=1, sticky='w', pady=10)
length_entry.insert(0, "16")  # Default password length

# Checkbuttons for character options
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
special_var = tk.BooleanVar(value=False)

def styled_checkbutton(text, var, row):
    return tk.Checkbutton(container, text=text, variable=var,
                          fg=fg_color, bg=bg_color, selectcolor=bg_color,
                          activebackground=bg_color, font=("Segoe UI", 16),
                          onvalue=True, offvalue=False)

uppercase_check = styled_checkbutton("Include Uppercase Letters (A-Z)", uppercase_var, 2)
uppercase_check.grid(row=2, column=0, columnspan=2, sticky='w', pady=5)
lowercase_check = styled_checkbutton("Include Lowercase Letters (a-z)", lowercase_var, 3)
lowercase_check.grid(row=3, column=0, columnspan=2, sticky='w', pady=5)
numbers_check = styled_checkbutton("Include Numbers (0-9)", numbers_var, 4)
numbers_check.grid(row=4, column=0, columnspan=2, sticky='w', pady=5)
special_check = styled_checkbutton("Include Special Characters (!@#...)", special_var, 5)
special_check.grid(row=5, column=0, columnspan=2, sticky='w', pady=5)

# Generate button
generate_button = tk.Button(container, text="Generate Password", command=on_generate,
                            bg=button_color, fg=bg_color, font=("Segoe UI", 20, "bold"),
                            activebackground=accent_color, activeforeground=bg_color, padx=20, pady=10)
generate_button.grid(row=6, column=0, columnspan=2, pady=(40, 20), sticky='ew')

# Password output label and entry
password_label = tk.Label(container, text="Generated Password:", fg=fg_color, bg=bg_color, font=("Segoe UI", 18))
password_label.grid(row=7, column=0, sticky='w', pady=10, padx=(0,20))
password_entry = tk.Entry(container, font=("Segoe UI", 18), width=40, justify='center', state='readonly')
password_entry.grid(row=7, column=1, sticky='w', pady=10)

# Instruction label at bottom
instr_label = tk.Label(container, text="Press ESC to exit full screen.", fg=fg_color, bg=bg_color, font=("Segoe UI", 12, "italic"))
instr_label.grid(row=8, column=0, columnspan=2, pady=30)

# Bind ESC key to exit fullscreen
def exit_fullscreen(event=None):
    root.attributes('-fullscreen', False)
root.bind('<Escape>', exit_fullscreen)

# Run the app
root.mainloop()
