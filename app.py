import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# RSA Utility Functions
def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open("private_key.pem", "wb") as private_file:
            private_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        public_key = private_key.public_key()
        with open("public_key.pem", "wb") as public_file:
            public_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        messagebox.showinfo("Success", "RSA keys generated successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")

def sign_message(message, private_key_path):
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        signature = private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign message: {str(e)}")
        return ""

def verify_signature(message, signature, public_key_path):
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        signature = base64.b64decode(signature)
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# GUI Application Class
class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature Tool")
        self.root.configure(bg="gray")
        self.root.state('zoomed')  # Maximize window

        # Layout split: left and right
        self.left_frame = tk.Frame(root, bg="#444", width=300)
        self.left_frame.pack(side="left", fill="y")

        self.right_frame = tk.Frame(root, bg="lightgray")
        self.right_frame.pack(side="left", expand=True, fill="both", padx=20, pady=20)

        # LEFT PANEL CONTENT
        self.title_label = tk.Label(
            self.left_frame,
            text="DIGITAL\nSIGNATURE\nVERIFICATION",
            bg="#444", fg="white",
            font=("Bookman Old Style", 24, "bold"),
            justify="center"
        )
        self.title_label.place(relx=0.5, rely=0.5, anchor="center")

        # RIGHT PANEL CONTENT
        self.build_right_panel()

    def build_right_panel(self):
        # Generate RSA Keys Button
        self.generate_keys_button = tk.Button(
            self.right_frame, text="GENERATE RSA KEYS", font=("Bookman Old Style", 14, "bold"),
            command=self.generate_keys, bg="lightgray", fg="black"
        )
        self.generate_keys_button.pack(pady=10)

        # Message to sign
        tk.Label(self.right_frame, text="Enter Message to Sign:", font=("Bookman Old Style", 12), bg="lightgray").pack(anchor="w")
        self.sign_message_textbox = tk.Text(self.right_frame, font=("Bookman Old Style", 12), height=5)
        self.sign_message_textbox.pack(fill="x", pady=5)

        self.sign_message_button = tk.Button(
            self.right_frame, text="SIGN MESSAGE", font=("Bookman Old Style", 14, "bold"),
            command=self.sign_message, bg="lightgray", fg="black"
        )
        self.sign_message_button.pack(pady=10)

        # Display signature
        tk.Label(self.right_frame, text="Generated Digital Signature:", font=("Bookman Old Style", 12), bg="lightgray").pack(anchor="w")
        self.signature_display_textbox = tk.Text(self.right_frame, font=("Bookman Old Style", 12), height=5)
        self.signature_display_textbox.pack(fill="x", pady=5)

        # Message to verify
        tk.Label(self.right_frame, text="Enter Message to Verify:", font=("Bookman Old Style", 12), bg="lightgray").pack(anchor="w")
        self.verify_message_textbox = tk.Text(self.right_frame, font=("Bookman Old Style", 12), height=5)
        self.verify_message_textbox.pack(fill="x", pady=5)

        # Signature to verify
        tk.Label(self.right_frame, text="Enter Digital Signature to Verify:", font=("Bookman Old Style", 12), bg="lightgray").pack(anchor="w")
        self.signature_verify_textbox = tk.Text(self.right_frame, font=("Bookman Old Style", 12), height=3)
        self.signature_verify_textbox.pack(fill="x", pady=5)

        # Verify button
        self.verify_signature_button = tk.Button(
            self.right_frame, text="VERIFY SIGNATURE", font=("Bookman Old Style", 14, "bold"),
            command=self.verify_signature, bg="lightgray", fg="black"
        )
        self.verify_signature_button.pack(pady=10)

    def generate_keys(self):
        generate_rsa_keys()

    def sign_message(self):
        message = self.sign_message_textbox.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to sign.")
            return
        signature = sign_message(message, "private_key.pem")
        self.signature_display_textbox.delete("1.0", tk.END)
        self.signature_display_textbox.insert("1.0", signature)

    def verify_signature(self):
        message = self.verify_message_textbox.get("1.0", tk.END).strip()
        signature = self.signature_verify_textbox.get("1.0", tk.END).strip()
        if not message or not signature:
            messagebox.showwarning("Warning", "Please enter both message and signature to verify.")
            return
        if verify_signature(message, signature, "public_key.pem"):
            messagebox.showinfo("Verification", "Signature is valid. The message is authentic.")
        else:
            messagebox.showerror("Verification", "Signature verification failed. Ensure the message and signature are correct.")

# Run the Application
if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
