import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import pyotp
import json
import os
import re
import csv
import time
from cryptography.fernet import Fernet
from hashlib import sha256
import base64

class TOTPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TOTP Generator")
        self.root.geometry("400x500")

        self.file_path = "totp_codes.json"
        self.master_password = None
        self.app_list = []
        self.attempts = 0  # Track the number of incorrect password attempts

        # TOTP interval is usually 30 seconds
        self.totp_interval = 30

        # Prompt for master password first
        self.prompt_for_password()

        # Initialize the listbox before loading codes
        self.otp_listbox = tk.Listbox(root, width=50)
        self.otp_listbox.pack(pady=10)

        # Load codes from file if they exist
        if self.load_codes():
            self.load_otp_listbox()

        # Counter Label for OTP refresh countdown
        self.counter_label = tk.Label(root, text=f"Time until code refresh: {self.totp_interval} seconds")
        self.counter_label.pack(pady=5)

        # Application Name Label and Entry
        tk.Label(root, text="Application Name:").pack(pady=5)
        self.app_name_entry = tk.Entry(root)
        self.app_name_entry.pack(pady=5)

        # Secret Key Label and Entry
        tk.Label(root, text="Secret Key (Base32):").pack(pady=5)
        self.secret_entry = tk.Entry(root)
        self.secret_entry.pack(pady=5)

        # Add OTP Button
        self.add_button = tk.Button(root, text="Add OTP", command=self.add_otp)
        self.add_button.pack(pady=10)

        # Delete OTP Button
        self.delete_button = tk.Button(root, text="Delete OTP", command=self.delete_otp)
        self.delete_button.pack(pady=5)
        
        # Export to CSV Button
        self.export_button = tk.Button(root, text="Export keys to CSV", command=self.export_to_csv)
        self.export_button.pack(pady=5)

        # About Button
        self.about_button = tk.Button(root, text="About", command=self.show_about)
        self.about_button.pack(pady=5)

        # Start the OTP timer
        self.update_otp()

    def prompt_for_password(self):
        """Prompt the user for a master password."""
        while self.attempts < 5:  # Allow up to 5 attempts
            self.master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
            if self.master_password:
                break
            else:
                messagebox.showerror("Error", "Master password is required!")

        if not self.master_password:
            self.root.quit()

        # Hash the password to derive a key
        self.fernet_key = base64.urlsafe_b64encode(sha256(self.master_password.encode()).digest())

    def add_otp(self):
        app_name = self.app_name_entry.get().strip()
        secret = self.secret_entry.get().strip()

        if app_name and secret:
            # Validate Base32 secret
            if not self.is_valid_base32(secret):
                messagebox.showerror("Error", "Invalid Base32 secret key.")
                return
            
            # If valid, create TOTP instance and validate OTP generation
            try:
                totp = pyotp.TOTP(secret)
                totp.now()  # Attempt to generate OTP to check if secret is valid
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate OTP: {e}")
                return  # Return early if OTP generation fails

            # If the secret is valid, add to the list and save
            self.app_list.append({"app_name": app_name, "secret": secret})
            self.save_codes()  # Save codes to file
            self.otp_listbox.insert(tk.END, f"{app_name}: {self.generate_otp(secret)}")
            
            # Clear input fields
            self.app_name_entry.delete(0, tk.END)
            self.secret_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("Input Error", "Please fill both fields.")

    def delete_otp(self):
        selected_index = self.otp_listbox.curselection()
        if selected_index:
            selected_item = self.app_list[selected_index[0]]

            # Confirm deletion
            if messagebox.askyesno("Confirm", f"Delete {selected_item['app_name']}?"):
                del self.app_list[selected_index[0]]
                self.save_codes()  # Save updated codes to file
                self.update_listbox()  # Update the listbox display
        else:
            messagebox.showwarning("Selection Error", "Please select an OTP entry to delete.")

    def update_listbox(self):
        # Save the current selection
        current_selection = self.otp_listbox.curselection()

        self.otp_listbox.delete(0, tk.END)  # Clear current listbox
        for entry in self.app_list:
            otp = self.generate_otp(entry['secret'])
            self.otp_listbox.insert(tk.END, f"{entry['app_name']}: {otp}")

        # Restore the selection
        if current_selection:
            self.otp_listbox.select_set(current_selection)


    def generate_otp(self, secret):
        try:
            totp = pyotp.TOTP(secret)
            return totp.now()  # Generate current OTP
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate OTP: {e}")
            return "Error"

    def save_codes(self):
        # Encrypt data
        fernet = Fernet(self.fernet_key)
        encrypted_data = fernet.encrypt(json.dumps(self.app_list).encode())

        with open(self.file_path, 'wb') as file:
            file.write(encrypted_data)

    def load_codes(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt data
            fernet = Fernet(self.fernet_key)
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                self.app_list = json.loads(decrypted_data.decode())
                return True
            except Exception:
                self.attempts += 1
                messagebox.showerror("Error", "Password is incorrect. Please try again.")
                if self.attempts >= 5:
                    messagebox.showerror("Error", "Too many incorrect attempts. Exiting the application.")
                    self.root.quit()
                else:
                    self.prompt_for_password()  # Re-prompt for the password
                    return self.load_codes()  # Try loading codes again
        return True

    def load_otp_listbox(self):
        for entry in self.app_list:
            otp = self.generate_otp(entry['secret'])
            self.otp_listbox.insert(tk.END, f"{entry['app_name']}: {otp}")

    def update_otp(self):
        # Clear the listbox and reload the OTPs with current values
        self.update_listbox()

        # Get current time and calculate remaining time in the 30-second TOTP cycle
        current_time = time.time()
        time_remaining = self.totp_interval - int(current_time) % self.totp_interval

        # Update the countdown label
        self.counter_label.config(text=f"Time until code refresh: {time_remaining} seconds")

        # Call this function again after 1 second to update both OTPs and the countdown timer
        self.root.after(1000, self.update_otp)

    def is_valid_base32(self, secret):
        """ Check if the provided secret is a valid Base32 string. """
        base32_pattern = re.compile("^[A-Z2-7]+=*$")
        
        if base32_pattern.match(secret.upper()):
            try:
                # Normalize the padding for Base32
                while len(secret) % 8 != 0:
                    secret += '='  # Add padding

                # Attempt to create a TOTP instance; will raise ValueError if invalid
                pyotp.TOTP(secret)
                return True
            except Exception:
                return False
        return False

    def show_about(self):
        """ Display the About information. """
        messagebox.showinfo("About", "This TOTP Generator app allows you to securely store and generate one-time passcodes (OTPs) using Base32 secrets.")

    def export_to_csv(self):
        """ Export the app names and Base32 secrets to a CSV file. """
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Application Name", "Base32 Secret"])
                for entry in self.app_list:
                    writer.writerow([entry['app_name'], entry['secret']])
            messagebox.showinfo("Export Complete", f"Data exported to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TOTPApp(root)
    root.mainloop()
