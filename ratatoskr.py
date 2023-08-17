from stegano import lsb
import os

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
    def hide_message_in_image(self, message, password, image_path, output_path):
        try:
            secret = lsb.hide(image_path, f"{password}\n{message}")
            secret.save(output_path)
            return True
        except Exception as e:
            print("Error while hiding message:", e)
            return False

    def reveal_hidden_message_from_image(self, image_path, password):
        try:
            secret = lsb.reveal(image_path)
            stored_password, hidden_message = secret.split('\n', 1)
            if password == stored_password:
                return hidden_message
            else:
                print("Incorrect password. Message cannot be revealed.")
                return None
        except Exception as e:
            print("Error while revealing message:", e)
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
