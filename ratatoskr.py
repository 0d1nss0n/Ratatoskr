from stegano import lsb
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

print("""
                               ░▒▓█▓░
                              ░▓█████░
                      ░██░   ░███████▓░
                     ░▓██▓░░░▓█████████▒░
                  ░▓▓████▒░░▓███████████▓▒░
                ░▒██████████░░▓██████████████▓░
               ░▓██▓▓█████████▒░▒▓██████████████▒░
               ▓█████████████████▒░░▒▓████████████▓░
                ▓████████████████████▓▒░▓███████████▒░
                    ░▒▓█████████████████▓▒░▓█████████▒░
                     ░░████████████████████▒░▓████████░
                    ░████████▓▒▒▒▓▓▓███████▓░▓███████▓░
                  ░▓██████▓░▒▓████▓▓█████████░▓███████░
                ░▒███████▒░██████████████████▒░███████░
                ░▒█▒░    ░███████████████████▓░███████░
                  ░▓░     ░███████████████████▒░██████▒
                          ░▓██████████████████░▓█████▓░
                           ░▓████████████████░▒█████▓░
                           ░▒▓█████████████░▒████▓░
                          ░▓▓▓▓████████████▒░▒▓▓▒░

██████   █████  ████████  █████  ████████  ██████  ███████ ██   ██ ██████  
██   ██ ██   ██    ██    ██   ██    ██    ██    ██ ██      ██  ██  ██   ██ 
██████  ███████    ██    ███████    ██    ██    ██ ███████ █████   ██████  
██   ██ ██   ██    ██    ██   ██    ██    ██    ██      ██ ██  ██  ██   ██ 
██   ██ ██   ██    ██    ██   ██    ██     ██████  ███████ ██   ██ ██   ██ 
                                                                           
       -Steganography Tool to hide and reveal messages using a password                                                       
       -Created by: 0D1NSS0N
""")

class DataSteganographyMessenger:
    def generate_encryption_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def handle_path_quotes(self, path):
        # Remove quotes if present in path
        return path.strip("\"'")

    def hide_message_in_image(self, message, password, image_path, output_path):
        image_path, output_path = self.handle_path_quotes(image_path), self.handle_path_quotes(output_path)

        salt = os.urandom(16)  # Generate a new salt
        key = self.generate_encryption_key(password, salt)
        cipher_suite = Fernet(key)
        encrypted_message = cipher_suite.encrypt(message.encode('utf-8'))
        
        data_to_hide = base64.urlsafe_b64encode(salt).decode('utf-8') + base64.urlsafe_b64encode(encrypted_message).decode('utf-8')
        secret_image = lsb.hide(image_path, data_to_hide)
        secret_image.save(output_path)
        return True

    def reveal_hidden_message_from_image(self, image_path, password):
        image_path = self.handle_path_quotes(image_path)
        hidden_data = lsb.reveal(image_path)
        salt_b64, encrypted_message_b64 = hidden_data[:24], hidden_data[24:]
        salt = base64.urlsafe_b64decode(salt_b64)
        key = self.generate_encryption_key(password, salt)
        cipher_suite = Fernet(key)
        try:
            encrypted_message = base64.urlsafe_b64decode(encrypted_message_b64)
            decrypted_message = cipher_suite.decrypt(encrypted_message)
            return decrypted_message.decode('utf-8')
        except Exception as e:
            print(f"Error while revealing message: {e}")
            return None

# Encrypt the message using the provided password
def encrypt_message(message, password):
    key, salt = generate_encryption_key(password)
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(message.encode('utf-8'))
    return encrypted_text, salt

# Decrypt the message using the provided password and salt
def decrypt_message(encrypted_message, password, salt):
    key = generate_encryption_key(password, salt)  # Pass the salt here
    cipher_suite = Fernet(key)
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_message)
        return decrypted_text.decode('utf-8')
    except Exception as e:
        print("Decryption failed:", e)
        return None

def hide_message(messenger):
    password = input("Enter a password: ")
    message = input("Enter the message: ")
    image_path = input("Enter the path of the image: ")
    output_path = input("Enter the output path for the new image: ")
    
    if messenger.hide_message_in_image(message, password, image_path, output_path):
        print("Message hidden in the image.")
    else:
        print("Failed to hide message.")

def reveal_message(messenger):
    image_path = input("Enter the path of the image with the hidden message: ")
    password = input("Enter the password to reveal the message: ")
    
    hidden_message = messenger.reveal_hidden_message_from_image(image_path, password)
    
    if hidden_message:
        print("\nHidden message:", hidden_message)
    else:
        print("Failed to reveal message.")


def main():
    messenger = DataSteganographyMessenger()

    while True:
        print("\n1. Hide message in an image")
        print("2. Reveal hidden message from image")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            hide_message(messenger)
        elif choice == "2":
            reveal_message(messenger)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()
