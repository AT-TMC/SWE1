import tkinter as tk
from tkinter import messagebox
import pyperclip
import requests


class UndoEntry(tk.Entry):
    def __init__(self, master=None, **kwargs):
        tk.Entry.__init__(self, master, **kwargs)
        self.undo_stack = [(0, "")]
        self.bind("<Key>", self.on_key)

    def on_key(self, event):
        self.undo_stack.append((self.index(tk.INSERT), self.get()))

    def on_paste(self):
        clipboard_content = pyperclip.paste()
        if self.get() == placeholder_text_1 or self.get() == placeholder_text_2:
            self.delete(0, tk.END)
            self.config(fg="black")
        insert_index = self.index(tk.INSERT)
        self.insert(tk.END, clipboard_content)
        self.undo_stack.append((insert_index, clipboard_content))

    def undo(self):
        if len(self.undo_stack) > 1:
            confirm_undo = messagebox.askyesno(
                "Undo",
                "Are you sure you want to undo your last action?"
                )
            if confirm_undo:
                self.undo_stack.pop()
                self.delete(0, tk.END)
                for index, content in self.undo_stack[-1:]:
                    self.insert(index, content)


def caesar_cipher(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted_char = chr((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26 + ord('a' if char.islower() else 'A'))
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text


def encrypt():
    input_text_1 = entry_1.get()
    encrypted_text = caesar_cipher(input_text_1, 34)
    entry_2.delete(0, tk.END)
    entry_2.insert(0, encrypted_text)
    entry_2.config(fg="black")


def decrypt():
    encrypted_text = entry_2.get()
    decrypted_text = caesar_cipher(encrypted_text, -34)
    entry_1.delete(0, tk.END)
    entry_1.insert(0, decrypted_text)
    entry_1.config(fg="black")


def info():
    help_text = """
    Welcome to the Message Encryption App Help Guide!

    This app allows you to encrypt and decrypt messages using a Caesar cipher.

    How to Use:
    1. Enter your message in the 'Encrypt' box.
    2. Click 'Encrypt' to encrypt the message.
    3. The encrypted message will appear in the 'Decrypt' box.
    4. To decrypt, click 'Decrypt'.

    Additional Features:
    - Use the 'Paste' buttons to paste content from the clipboard into the text boxes.
    - 'Undo' buttons allow you to undo your last text modification.
    - Click 'Save' to save the encrypted message to the server.

    Logging In:
    - Enter your username and password to log in.
    - If you are a new user, click 'Register' to create an account.

    Logging Out:
    - Click 'Log Out' to return to the login screen.

    Note:
    - Ensure you remember your username and password these will be required to retrieve your encrypted message after logging out.
    - The app uses a Caesar cipher with a fixed shift value of 34.

    Have fun encrypting and decrypting your messages!
    """
    help_window = tk.Tk()
    help_window.title("Help")
    help_window.geometry("700x400")

    help_label = tk.Label(
        help_window,
        text=help_text,
        anchor="w",
        justify="left"
        )
    help_label.pack(padx=10, pady=10)

    help_window.mainloop()


def on_paste_1():
    entry_1.on_paste()


def on_paste_2():
    entry_2.on_paste()


def on_undo_1():
    entry_1.undo()


def on_undo_2():
    entry_2.undo()


def clear_placeholder_1(event):
    if entry_1.get() == placeholder_text_1:
        entry_1.delete(0, tk.END)
        entry_1.config(fg="black")


def restore_placeholder_1(event):
    if not entry_1.get():
        entry_1.insert(0, placeholder_text_1)
        entry_1.config(fg="grey")


def clear_placeholder_2(event):
    if entry_2.get() == placeholder_text_2:
        entry_2.delete(0, tk.END)
        entry_2.config(fg="black")


def restore_placeholder_2(event):
    if not entry_2.get():
        entry_2.insert(0, placeholder_text_2)
        entry_2.config(fg="grey")


def authenticate(username, password):
    auth_url = 'http://localhost:5000/authenticate'
    response = requests.post(auth_url, json={
        'username': username,
        'password': password
        }
        )
    if response.status_code == 200:
        return True
    else:
        return False


def register(username, password, encrypted_message):
    register_url = 'http://localhost:5000/register'
    response = requests.post(register_url, json={
        'username': username,
        'password': password,
        'encrypted_message': encrypted_message
        }
        )
    if response.status_code == 201:
        return True
    else:
        return False


def save_message(username, password):
    encrypted_message = entry_2.get()

    if username and password and encrypted_message:
        confirm_save = messagebox.askyesno(
            "Save Message",
            "Are you sure you want to save the decrypted message?\n"
            "This will overwrite any existing encrypted message with your current username and password."
            )
        if confirm_save:
            save_url = 'http://localhost:5000/save_message'
            response = requests.post(
                save_url, json={
                    'username': username,
                    'password': password,
                    'encrypted_message': encrypted_message
                    }
                    )

            if response.status_code == 200:
                messagebox.showinfo(
                    "Message Saved", "Message saved successfully!"
                    )
            else:
                messagebox.showerror("Error", "Failed to save message.")
    else:
        messagebox.showerror(
            "Error", "Please provide a username, password, and message."
            )


def login():
    username = username_entry.get()
    password = password_entry.get()
    if authenticate(username, password):
        login_window.destroy()
        encrypted_message = fetch_encrypted_message(username, password)
        show_main_gui(username, password, encrypted_message)
    else:
        login_status.config(text="Invalid credentials")


def logout(window):
    confirm_logout = messagebox.askyesno(
        "Logout", "Are you sure you want to log out?\n"
        "Logging out without saving will result in the loss of your encrypted message."
        )
    if confirm_logout:
        window.destroy()
        create_login_window()


def fetch_encrypted_message(username, password):
    get_message_url = f'http://localhost:5000/get_message/{username}'
    response = requests.get(get_message_url)
    if response.status_code == 200:
        encrypted_message = response.json().get('encrypted_message', '')
        return encrypted_message
    else:
        messagebox.showerror("Error", "Failed to fetch encrypted message.")
        return ''


def register_new_user():
    username = username_entry.get()
    password = password_entry.get()
    if username and password:
        encrypted_message = caesar_cipher("Default message", 34)
        if register(username, password, encrypted_message):
            messagebox.showinfo(
                "Registration Successful", "User registered successfully!"
                )
            login_window.destroy()
            show_main_gui(username, password)
        else:
            messagebox.showerror(
                "Registration Failed", "Failed to register user."
                )
    else:
        messagebox.showerror(
            "Error", "Please provide a username and password."
            )


def show_main_gui(username, password, encrypted_message=None):
    global root
    root = tk.Tk()
    root.title("Message Encryption App")
    root.geometry("400x400")

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - 400) // 2
    y = (screen_height - 200) // 2
    root.geometry("+{}+{}".format(x, y))

    username_label = tk.Label(root, text="Logged in as: " + username)
    username_label.pack()

    global placeholder_text_1
    placeholder_text_1 = "Enter text to encrypt"
    global placeholder_text_2
    placeholder_text_2 = "Enter text to decrypt"

    label_1 = tk.Label(root, text="Encrypt your message:")
    label_1.pack()
    global entry_1
    entry_1 = UndoEntry(root, width=30, fg="grey")
    entry_1.insert(0, placeholder_text_1)
    entry_1.bind("<FocusIn>", clear_placeholder_1)
    entry_1.bind("<FocusOut>", restore_placeholder_1)
    entry_1.pack()

    button_frame_1 = tk.Frame(root)
    button_frame_1.pack()
    paste_button_1 = tk.Button(button_frame_1, text="Paste",
                               command=on_paste_1)
    paste_button_1.pack(side=tk.LEFT)
    undo_button_1 = tk.Button(button_frame_1, text="Undo", command=on_undo_1)
    undo_button_1.pack(side=tk.LEFT)
    encrypt_button = tk.Button(button_frame_1, text="Encrypt", command=encrypt)
    encrypt_button.pack(side=tk.LEFT)
    info_button = tk.Button(button_frame_1, text="Info", command=info)
    info_button.pack(side=tk.LEFT)

    label_2 = tk.Label(root, text="Decrypt your message:")
    label_2.pack()
    global entry_2
    entry_2 = UndoEntry(root, width=30, fg="grey")
    entry_2.insert(0, placeholder_text_2)
    entry_2.bind("<FocusIn>", clear_placeholder_2)
    entry_2.bind("<FocusOut>", restore_placeholder_2)
    entry_2.pack()

    button_frame_2 = tk.Frame(root)
    button_frame_2.pack()
    paste_button_2 = tk.Button(button_frame_2, text="Paste",
                               command=on_paste_2)
    paste_button_2.pack(side=tk.LEFT)
    undo_button_2 = tk.Button(button_frame_2, text="Undo", command=on_undo_2)
    undo_button_2.pack(side=tk.LEFT)
    decrypt_button = tk.Button(button_frame_2, text="Decrypt", command=decrypt)
    decrypt_button.pack(side=tk.LEFT)

    save_button = tk.Button(button_frame_2, text="Save",
                            command=lambda: save_message(username, password))
    save_button.pack(side=tk.LEFT)

    logout_button = tk.Button(button_frame_2, text="Log Out",
                              command=lambda: logout(root))
    logout_button.pack(side=tk.LEFT)

    if encrypted_message:
        entry_2.delete(0, tk.END)
        entry_2.insert(0, encrypted_message)
        entry_2.config(fg="black")

    root.mainloop()


def create_login_window():
    global login_window
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("600x600")

    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = (screen_width - 300) // 2
    y = (screen_height - 200) // 2
    login_window.geometry("+{}+{}".format(x, y))
    welcome_message = """
    Welcome to the Message Encryption App!

    This app allows you to securely encrypt and decrypt messages using a Caesar cipher.

    Why Use Encryption?

    **Privacy**: Your messages are scrambled, making it difficult for unauthorized users to read them.
    **Confidentiality**: Keep your sensitive information safe from prying eyes.
    **Security**: Add an extra layer of protection to your messages.
    **Data Protection**: Safeguard your communications from potential breaches.

    If you are a new user, please register with a unique username and password.

    Enjoy encrypting and decrypting your messages!
    """

    welcome_label = tk.Label(login_window, text=welcome_message,
                             justify=tk.LEFT, padx=10, pady=10)
    welcome_label.pack()

    username_label = tk.Label(login_window, text="Username:")
    username_label.pack()

    global username_entry
    username_entry = tk.Entry(login_window, width=30)
    username_entry.pack()

    password_label = tk.Label(login_window, text="Password:")
    password_label.pack()

    global password_entry
    password_entry = tk.Entry(login_window, width=30, show="*")
    password_entry.pack()

    login_button = tk.Button(login_window, text="Login", command=login)
    login_button.pack()

    register_button = tk.Button(login_window, text="Register",
                                command=register_new_user)
    register_button.pack()

    global login_status
    login_status = tk.Label(login_window, text="")
    login_status.pack()

    login_window.mainloop()


create_login_window()
