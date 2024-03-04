import tkinter as tk
from tkinter import messagebox
import pyperclip


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
    input_text_2 = caesar_cipher(input_text_1, 34)
    entry_2.delete(0, tk.END)
    entry_2.insert(0, input_text_2)
    entry_2.config(fg="black")


def decrypt():
    input_text_2 = entry_2.get()
    input_text_1 = caesar_cipher(input_text_2, -34)
    entry_1.delete(0, tk.END)
    entry_1.insert(0, input_text_1)
    entry_1.config(fg="black")

def info():
    help_text = """
    This is a simple message encryption app.
    - Enter your message in the 'Encrypt' box.
    - Click 'Encrypt' to encrypt the message.
    - Encrypted message will appear in the 'Decrypt' box.
    - To decrypt, click 'Decrypt'.
    """
    messagebox.showinfo("Help", help_text)



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
    return username == "Ant" and password == "123"


def login():
    global username
    username = username_entry.get()
    password = password_entry.get()
    if authenticate(username, password):
        login_window.destroy()
        show_main_gui()
    else:
        login_status.config(text="Invalid credentials")


def show_main_gui():
    root = tk.Tk()
    root.title("Message Encryption App")
    root.geometry("400x200")

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
    paste_button_1 = tk.Button(button_frame_1, text="Paste", command=on_paste_1)
    paste_button_1.pack(side=tk.LEFT)
    undo_button_1 = tk.Button(button_frame_1, text="Undo", command=on_undo_1)
    undo_button_1.pack(side=tk.LEFT)
    submit_button_1 = tk.Button(button_frame_1, text="Encrypt", command=encrypt)
    submit_button_1.pack(side=tk.LEFT)
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
    paste_button_2 = tk.Button(button_frame_2, text="Paste", command=on_paste_2)
    paste_button_2.pack(side=tk.LEFT)
    undo_button_2 = tk.Button(button_frame_2, text="Undo", command=on_undo_2)
    undo_button_2.pack(side=tk.LEFT)
    submit_button_2 = tk.Button(button_frame_2, text="Decrypt", command=decrypt)
    submit_button_2.pack(side=tk.LEFT)
    save_button = tk.Button(button_frame_2, text="Save", command=on_paste_2)
    save_button.pack(side=tk.LEFT)

    root.mainloop()


login_window = tk.Tk()
login_window.title("Login")

explanation_label = tk.Label(login_window, text="Welcome to the Message Encryption App!\nEncryption is a safe and easy way to protect your private messages so no one will be able to decode them without your approval\nIn under 5 seconds you will be able to encrypt or decrypt your private message from wandering eyes.\nTo start using this app you must provide us a username and unique password that will be associated with your message!")
explanation_label.pack()

username_label = tk.Label(login_window, text="Username:")
username_label.pack()
username_entry = tk.Entry(login_window)
username_entry.pack()

password_label = tk.Label(login_window, text="Password:")
password_label.pack()
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

login_button = tk.Button(login_window, text="Login", command=login)
login_button.pack()

login_status = tk.Label(login_window, text="")
login_status.pack()

login_window.mainloop()
