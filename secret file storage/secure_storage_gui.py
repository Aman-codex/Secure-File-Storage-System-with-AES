import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from getpass import getpass  # not used in GUI but kept for consistency
import os
import secure_storage  # make sure secure_storage.py is in the same folder


class SecureStorageGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure File Storage (AES)")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        # --- File selection ---
        self.file_label = tk.Label(root, text="No file selected", anchor="w")
        self.file_label.pack(pady=10, fill="x", padx=20)

        self.select_btn = tk.Button(root, text="📂 Select File", command=self.select_file)
        self.select_btn.pack(pady=5)

        # --- Password fields ---
        self.pw_label = tk.Label(root, text="Enter Password:")
        self.pw_label.pack(pady=(20, 0))
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.pack()

        self.pw_confirm_label = tk.Label(root, text="Confirm Password (for encryption):")
        self.pw_confirm_label.pack(pady=(10, 0))
        self.password_confirm_entry = tk.Entry(root, show="*", width=40)
        self.password_confirm_entry.pack()

        # --- Buttons for actions ---
        self.encrypt_btn = tk.Button(root, text="🔒 Encrypt File", command=self.encrypt_file, width=20)
        self.encrypt_btn.pack(pady=10)

        self.decrypt_btn = tk.Button(root, text="🔓 Decrypt File", command=self.decrypt_file, width=20)
        self.decrypt_btn.pack(pady=5)

        # --- Status area ---
        self.status = tk.Label(root, text="", fg="blue", wraplength=400)
        self.status.pack(pady=20)

        # --- Optional progress bar ---
        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", padx=20, pady=5)

        self.selected_file = None

    def select_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.selected_file = filepath
            self.file_label.config(text=f"Selected: {os.path.basename(filepath)}")

    def encrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return

        pw = self.password_entry.get()
        pw2 = self.password_confirm_entry.get()
        if not pw or not pw2:
            messagebox.showerror("Error", "Please enter and confirm a password.")
            return
        if pw != pw2:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        try:
            self.progress.start()
            outfile = secure_storage.encrypt_file(self.selected_file, pw)
            self.progress.stop()
            self.status.config(text=f"✅ File encrypted: {outfile}", fg="green")
            messagebox.showinfo("Success", f"File encrypted successfully:\n{outfile}")
        except Exception as e:
            self.progress.stop()
            self.status.config(text=f"❌ Error: {str(e)}", fg="red")

    def decrypt_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return

        pw = self.password_entry.get()
        if not pw:
            messagebox.showerror("Error", "Please enter the password.")
            return

        try:
            self.progress.start()
            outfile = secure_storage.decrypt_file(self.selected_file, pw)
            self.progress.stop()
            self.status.config(text=f"✅ File decrypted: {outfile}", fg="green")
            messagebox.showinfo("Success", f"File decrypted successfully:\n{outfile}")
        except Exception as e:
            self.progress.stop()
            self.status.config(text=f"❌ Error: {str(e)}", fg="red")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureStorageGUI(root)
    root.mainloop()
