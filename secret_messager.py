from tkinter import *
from tkinter import messagebox
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# Padding for AES (should be 16 bytes)
BLOCK_SIZE = 16

def pad(s):
    """
    Pads the input string to be a multiple of BLOCK_SIZE.
    
    Parameters:
    s (bytes): The input string to be padded.
    
    Returns:
    bytes: The padded string.
    """
    padding_length = BLOCK_SIZE - len(s) % BLOCK_SIZE
    padding = chr(padding_length).encode()
    return s + padding * padding_length

def unpad(s):
    """
    Removes padding from the input string.
    
    Parameters:
    s (bytes): The padded string.
    
    Returns:
    bytes: The unpadded string.
    """
    padding_length = s[-1]
    return s[:-padding_length]

def get_key(password):
    """
    Generates a SHA-256 hash of the password.
    
    Parameters:
    password (str): The password to be hashed.
    
    Returns:
    bytes: The SHA-256 hash of the password.
    """
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def encrypt():
    """
    Encrypts the message using AES encryption and displays the encrypted message in a new window.
    """
    password = code.get()
    
    if password == "":
        messagebox.showerror("encryption", "Input Password")
        return
    
    screen1 = Toplevel(screen)
    screen1.title("encryption")
    screen1.geometry("400x200")
    screen1.configure(bg="#ed3833")
    
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("encryption", "No message to encrypt")
        return
    
    try:
        key = get_key(password)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode('utf-8'))
        encrypted_message = base64.b64encode(iv + cipher.encrypt(padded_message)).decode('utf-8')
        
        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen1, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)
        
        text2.insert(END, encrypted_message)
    except Exception as e:
        messagebox.showerror("encryption", f"Encryption failed: {str(e)}")

def decrypt():
    """
    Decrypts the message using AES decryption and displays the decrypted message in a new window.
    """
    password = code.get()
    
    if password == "":
        messagebox.showerror("encryption", "Input Password")
        return
    
    screen2 = Toplevel(screen)
    screen2.title("decryption")
    screen2.geometry("400x200")
    screen2.configure(bg="#00bd56")
    
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showerror("decryption", "No message to decrypt")
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

def main_screen():
    """
    Initializes and runs the main Tkinter window.
    """
    global screen
    global code
    global text1
    
    screen = Tk()
    screen.geometry("385x350")
    
    # icon
    image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Secret Messenger")
    
    def reset():
        """
        Resets the input fields.
        """
        code.set("")
        text1.delete(1.0, END)
    
    Label(text="Text zur Ver- und Entschlüsselung:", fg="black", font=('calibri', 13)).place(x=10, y=10)
    text1 = Text(font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=350, height=100)
    
    Label(text="Geheimer Schlüssel:", fg="black", font=("calibri", 13)).place(x=10, y=170)
    
    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)
    
    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=300)
    
    screen.mainloop()

main_screen()
