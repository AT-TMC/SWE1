import tkinter as tk
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


root = tk.Tk()
root.title("Message Encryption App")
root.geometry("400x200")

placeholder_text_1 = "Enter text to encrypt"
placeholder_text_2 = "Enter text to decrypt"

label_1 = tk.Label(root, text="Encrypt your message:")
label_1.pack()
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

label_2 = tk.Label(root, text="Decrypt your message:")
label_2.pack()
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

root.mainloop()
