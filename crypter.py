import json
import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_fernet(key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 16,
        iterations=100000,
    )
    derived_key = kdf.derive(key.encode())
    fernet_key = base64.urlsafe_b64encode(derived_key)
    f = Fernet(fernet_key)
    return f

def encrypt_json(file_path, key):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        f = generate_fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
        return True
    except Exception as e:
        print(e)
        return False

def decrypt_json(file_path, key):
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        f = generate_fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        data = json.loads(decrypted_data)
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        return True
    except InvalidToken:
        return False
    except Exception as e:
        print(e)
        return False

class EncryptDecryptApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Encrypt/Decrypt JSON")
        self.geometry("340x200")

        self.file_path = tk.StringVar()

        self.mode = tk.StringVar()
        self.mode.set("encrypt")

        ttk.Label(self, text="Mode:").grid(column=0, row=0, padx=10, pady=10, sticky=tk.W)
        ttk.OptionMenu(self, self.mode, "encrypt", "encrypt", "decrypt").grid(column=1, row=0, padx=10, pady=10)

        ttk.Label(self, text="File path:").grid(column=0, row=1, padx=10, pady=10, sticky=tk.W)
        ttk.Entry(self, textvariable=self.file_path).grid(column=1, row=1, padx=10, pady=10)
        ttk.Button(self, text="Browse", command=self.browse).grid(column=2, row=1, padx=10, pady=10)

        ttk.Label(self, text="Password:").grid(column=0, row=2, padx=10, pady=10, sticky=tk.W)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(column=1, row=2, padx=10, pady=10)

        ttk.Button(self, text="Submit", command=self.submit).grid(column=1, row=3, padx=10, pady=10)

    def browse(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        self.file_path.set(file_path)

    def submit(self):
        file_path = self.file_path.get()

        if not os.path.isfile(file_path):
            tk.messagebox.showerror("Error", "File not found")
            return

        key = self.password_entry.get()

        if self.mode.get() == "encrypt":
            if encrypt_json(file_path, key):
                tk.messagebox.showinfo("Success", "Successfully encrypted")
            else:
                tk.messagebox.showerror("Error", "Encryption error")
        elif self.mode.get() == "decrypt":
            if decrypt_json(file_path, key):
                tk.messagebox.showinfo("Success", "Successfully decrypted")
            else:
                tk.messagebox.showerror("Error", "Decryption failed, invalid key")

if __name__ == "__main__":
    app = EncryptDecryptApp()
    app.mainloop()