import tkinter as tk
from PIL import ImageTk, Image
import base64
from tkinter import messagebox
from tkinter.constants import END

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encryption_notes():
    note_title_in_file = note_title_entry.get()
    message = secret_note_text.get("1.0", END).strip()
    master_key = master_key_entry.get()

    if len(note_title_in_file) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        # encryption
        message_encrypted = encode(master_key, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{note_title_in_file}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{note_title_in_file}\n{message_encrypted}")
        finally:
            note_title_entry.delete(0, END)
            master_key_entry.delete(0, END)
            secret_note_text.delete("1.0", END)

def decryption_note():
    message_encrypted = secret_note_text.get("1.0", END).strip()
    master_key = master_key_entry.get()

    if len(message_encrypted) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(master_key, message_encrypted)
            secret_note_text.delete("1.0", END)
            secret_note_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!",message="Please enter encrypteed text!")

# Create the main window
window = tk.Tk()
window.title("Secret Notes")
window.minsize(width=300, height=700)

# Load the image
img = ImageTk.PhotoImage(Image.open("jaho.jpg"))

# Create and pack the label with the image
image_label = tk.Label(window, image=img)
image_label.pack()

# Keep a reference to the image to prevent it from being garbage collected
image_label.image = img

# notetitle
note_title = tk.Label(text="Note Title")
note_title.pack(pady=(50, 0))
note_title_entry = tk.Entry()
note_title_entry.pack()

# secretnote
secret_note_label = tk.Label(text="Secret Notes")
secret_note_label.pack(pady=(15, 0))
secret_note_text = tk.Text(width=30, height=15)
secret_note_text.pack()

# masterkey
master_key_label = tk.Label(text="Master Key")
master_key_label.pack(pady=(15, 0))
master_key_entry = tk.Entry()
master_key_entry.pack()

# save & encryption button
save_and_encryption_button = tk.Button(text="Save & Encryption", command=save_and_encryption_notes)
save_and_encryption_button.pack(pady=(15, 0))

# decryption button
decryption_button = tk.Button(text="Decryption", command=decryption_note)
decryption_button.pack(pady=(15, 0))

window.mainloop()
