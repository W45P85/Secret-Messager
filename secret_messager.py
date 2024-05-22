import base64
import webbrowser
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from tkinter import *
from tkinter import messagebox


BLOCK_SIZE = 16 # Padding for AES (should be 16 bytes)

def pad(s):
    """
    Add padding to a message to match the block size of AES.

    Parameters:
        s (bytes): The message to pad.

    Returns:
        bytes: The padded message.
    """
    padding_length = BLOCK_SIZE - len(s) % BLOCK_SIZE
    padding = chr(padding_length).encode()
    return s + padding * padding_length

def unpad(s):
    """
    Remove padding from a decrypted message.

    Parameters:
        s (bytes): The decrypted message.

    Returns:
        bytes: The unpadded message.
    """
    padding_length = s[-1]
    return s[:-padding_length]

def get_key(password):
    """
    Generate a key from the given password using SHA256.

    Parameters:
        password (str): The password to generate the key from.

    Returns:
        bytes: The generated key.
    """
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def check_password_strength(password):
    """
    Check the strength of a password and return a feedback message.
    
    Parameters:
        password (str): The password to check.
    
    Returns:
        str: A feedback message indicating the strength of the password.
    """
    # Minimum length requirement
    if len(password) < 8:
        return "Schlüssel ist zu kurz. Mindestens 8 Zeichen verwenden."
    
    # Check for both uppercase and lowercase letters
    if not any(char.isupper() for char in password) or not any(char.islower() for char in password):
        return "Mindestens ein Groß- und Kleinbuchstaben verwenden."
    
    # Check for digits
    if not any(char.isdigit() for char in password):
        return "Mindestens eine Ziffer verwenden."
    
    # Check for special characters
    special_characters = "!@#$%^&*()-_=+[{]}|;:,<.>/?"
    if not any(char in special_characters for char in password):
        return "Mindestens ein Sonderzeichen verwenden."
    
    return "Die Schlüsselstärke ist ausreichend."

def encrypt():
    """
    Encrypt a message using the provided key.
    """
    password = code.get()

    if password == "":
        messagebox.showerror("encryption", "Enter key")
        return

    # Check password strength
    strength_feedback = check_password_strength(password)
    if not strength_feedback == "Die Schlüsselstärke ist ausreichend.":
        messagebox.showwarning("encryption", strength_feedback)
        return

    screen1 = Toplevel(screen)
    screen1.title("encryption")
    screen1.geometry("400x250")
    screen1.configure(bg="#ed3833")

    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("encryption", "No message to encrypt.")
        return

    try:
        key = get_key(password)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode('utf-8'))
        encrypted_message = base64.b64encode(iv + cipher.encrypt(padded_message)).decode('utf-8')

        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, encrypted_message)

        # 'Sent via email' Button
        def send_email_wrapper():
            send_email(encrypted_message)

        Button(screen1, text="Send via Email", height="2", width=23, bg="#1089ff", fg="white", bd=0,
               command=send_email_wrapper).place(relx=0.5, rely=0.9, anchor=CENTER)
    except Exception as e:
        messagebox.showerror("encryption", f"Encryption failed: {str(e)}")


def decrypt():
    """
    Decrypt a message using the provided key.
    """
    password = code.get()

    if password == "":
        messagebox.showerror("encryption", "Schlüssel eingeben")
        return

    screen2 = Toplevel(screen)
    screen2.title("decryption")
    screen2.geometry("400x250")
    screen2.configure(bg="#00bd56")

    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("decryption", "Keine Nachricht zu entschlüsseln")
        return

    try:
        key = get_key(password)
        message_bytes = base64.b64decode(message)
        iv = message_bytes[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(message_bytes[AES.block_size:])
        decrypted_message = unpad(decrypted_message).decode('utf-8')

        Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
        text2 = Text(screen2, font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, decrypted_message)
    except Exception as e:
        messagebox.showerror("decryption", f"Decryption failed: {str(e)}")

def send_email(encrypted_message):
    """
    Open the default email client to send the encrypted message.

    Parameters:
        encrypted_message (str): The encrypted message to send.
    """
    email_content = f"Beginn der verschlüsselten Nachricht: \n\n{encrypted_message}"
    webbrowser.open('mailto:?subject=Encrypted%20Message&body=' + email_content)

def update_password_strength():
    """
    Update the visual feedback for password strength.
    """
    password = code.get()

    # Check password strength
    strength_feedback = check_password_strength(password)
    
    # Update label text and color based on password strength
    if strength_feedback == "Die Schlüsselstärke ist ausreichend.":
        strength_label.config(text="Schlüsselstärke: Stark", fg="green")
    else:
        strength_label.config(text=strength_feedback, fg="red")

def main_screen():
    """
    Create the main window of the application.
    """
    global screen
    global code
    global text1
    global strength_label

    screen = Tk()
    screen.geometry("380x440")

    # Icon
    image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Secret Messenger")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Text für Ver- und Entschlüsselung:", fg="black", font=('calibri', 13)).place(x=10, y=10)
    text1 = Text(font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=350, height=100)

    Label(text="Geheimer Schlüssel:", fg="black", font=("calibri", 13)).place(x=10, y=170)

    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)
    
    # Add label for password strength feedback
    strength_label = Label(text="Schlüsselstärke: ", fg="black", font=("calibri", 11))
    strength_label.place(x=10, y=250)

    # Add button to update password strength feedback
    Button(text="Check Password Strength", height="1", width=23, bg="#1089ff", fg="white", bd=0, command=update_password_strength).place(x=10, y=280)

    Button(text="VERSCHLÜSSELN", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10,
                                                                                                       y=330)
    Button(text="ENTSCHLÜSSELN.", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200,
                                                                                                       y=330)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=380)

    screen.mainloop()

main_screen()