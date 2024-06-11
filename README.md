<pre style="background-color: transparent; border: none;">

   _____                         _     __  __                                                 
  / ____|                       | |   |  \/  |                                                
 | (___    ___   ___  _ __  ___ | |_  | \  / |  ___  ___  ___   ___  _ __    __ _   ___  _ __ 
  \___ \  / _ \ / __|| '__|/ _ \| __| | |\/| | / _ \/ __|/ __| / _ \| '_ \  / _` | / _ \| '__|
  ____) ||  __/| (__ | |  |  __/| |_  | |  | ||  __/\__ \\__ \|  __/| | | || (_| ||  __/| |   
 |_____/  \___| \___||_|   \___| \__| |_|  |_| \___||___/|___/ \___||_| |_| \__, | \___||_|   
                                                                             __/ |            
                                                                            |___/             
<p align="center">Message Ninja: Stealthy, Silent, Secure!</p>
</pre>

Secret Messenger is a simple Tkinter-based application that allows users to encrypt and decrypt messages using a secret key. The encryption uses AES (Advanced Encryption Standard) for secure communication.

## Features

- Encrypt messages using AES encryption.
- Decrypt messages with the correct secret key.
- User-friendly interface with Tkinter.
- Support for handling special characters and padding.
- Easily send encrypted messages via email with just a click
- Check the strength of your passwords with simple visual feedback.

## Installation

1. **Install Python**
    1. Make sure Python is installed on your system. You can download and install it from [python.org](https://www.python.org/).

2. **Clone the repository:**

    ```
    git clone https://github.com/W45P85/Secret-Messenger
    cd secret-messenger
    ```

3. **Create and activate a virtual environment using Anaconda:**

    ```
    conda create -n secret-messenger-env python=3.11
    conda activate secret-messenger-env
    ```

4. **Install the required dependencies:**

    ```
    pip install pycryptodome
    pip install tkinter
    ```

## Usage

1. **Run the application:**

<img src="/img/doc/1.PNG" width="250">

    python secret_messager.py

2. **Encrypting a Message:**

<img src="/img/doc/2.PNG" width="250">

    - Enter your message in the text box.
    - Enter your secret key.
    - Click the `ENCRYPT` button.
    - The encrypted message will be displayed in a new window.

<img src="/img/doc/5.PNG" width="250">

3. **Decrypting a Message:**

    - Enter the encrypted message in the text box.
    - Enter the same secret key used for encryption.
    - Click the `DECRYPT` button.
    - The decrypted message will be displayed in a new window.

<img src="/img/doc/8.PNG" width="250">

4. **Email Sending:**

    After encrypting a message, you can send it via email by clicking on the "send via email" button. The encrypted message will be automatically inserted into the email body.

    Note: Make sure you have an internet connection and that a default email client is set up on your system to utilize the email feature.

<img src="/img/doc/5.PNG" width="250">

5. **Password Strength**

    A strong password must meet the following criteria:
    - Be at least 8 characters long.
    - Contain at least one uppercase letter and one lowercase letter.
    - Contain at least one digit.
    - Contain at least one special character, such as `!@#$%^&*()-_=+[{]}|;:,<.>/?`.

<img src="/img/doc/7.PNG" width="250">

## Dependencies

- tkinter
- pycryptodome


## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.


## License

This project is licensed under the MIT License. See the LICENSE file for more details.


### Explanation

1. **Features**: A brief overview of what the application does.
2. **Installation**: Step-by-step instructions to clone the repository, set up a virtual environment, and install dependencies.
3. **Usage**: Instructions on how to run the application and use its features.
4. **Dependencies**: A list of dependencies required for the project.
5. **Contributing**: Information on how to contribute to the project.
6. **License**: Information about the project's license.


# Technical Documentation
## Importing Required Libraries

```python
from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import webbrowser
```

- tkinter: Used to create the graphical user interface (GUI).
- messagebox: A submodule of tkinter for displaying message boxes.
- Crypto.Cipher.AES: For AES encryption and decryption.
- Crypto.Hash.SHA256: For hashing the password to create a key.
- Crypto.Random: To generate random initialization vectors (IV).
- base64: For encoding and decoding base64 strings.
- webbrowser: To open the default web browser for sending emails.


## Padding and Unpadding Functions
The tool employs padding and unpadding functions to ensure that input data conforms to the AES algorithm's block size requirements before encryption and is restored to its original state after decryption. This is essential for data integrity and proper encryption/decryption handling.

```python
BLOCK_SIZE = 16

def pad(s):
    padding_length = BLOCK_SIZE - len(s) % BLOCK_SIZE
    padding = chr(padding_length).encode()
    return s + padding * padding_length

def unpad(s):
    padding_length = s[-1]
    return s[:-padding_length]
```

- pad(s): Adds padding to the input string to make its length a multiple of BLOCK_SIZE.
- unpad(s): Removes padding from the input string.

## Key Derivation Function
The Key Derivation Function is responsible for generating a cryptographic key from the user-provided password. This function hashes the password using the SHA256 algorithm to create a secure key for AES encryption and decryption.

```python
def get_key(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()
```
- get_key(password): Hashes the password using SHA256 and returns the resulting key.

## Password Strength Check Function
The Password Strength Check Function evaluates the strength of a user-provided password to ensure it meets security requirements. It checks for criteria such as length, character variety, and the presence of special characters. By providing feedback on password strength, this function helps users create robust passwords that enhance the security of their encrypted messages.

```python
def check_password_strength(password):
    if len(password) < 8:
        return "Schlüssel ist zu kurz. Mindestens 8 Zeichen verwenden."
    if not any(char.isupper() for char in password) or not any(char.islower() for char in password):
        return "Mindestens ein Groß- und Kleinbuchstaben verwenden."
    if not any(char.isdigit() for char in password):
        return "Mindestens eine Ziffer verwenden."
    special_characters = "!@#$%^&*()-_=+[{]}|;:,<.>/?"
    if not any(char in special_characters for char in password):
        return "Mindestens ein Sonderzeichen verwenden."
    return "Die Schlüsselstärke ist ausreichend."

```
- check_password_strength(password): Checks if the password meets the specified criteria for length, character variety, and special characters.

## Encryption Function
The Encryption Function handles the process of encrypting messages using the AES algorithm. It first verifies the provided password strength and ensures that the input message is not empty. Upon successful validation, the function encrypts the message, pads it to the appropriate block size, and encodes it in base64 format for secure transmission. Finally, it displays the encrypted message in a graphical user interface for the user's convenience, allowing them to send the encrypted message via email if desired. Any encryption failures are appropriately handled and reported to the user.

```python
def encrypt():
    password = code.get()
    if password == "":
        messagebox.showerror("encryption", "Enter key")
        return

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

        def send_email_wrapper():
            send_email(encrypted_message)

        Button(screen1, text="Send with Email", height="2", width=23, bg="#1089ff", fg="white", bd=0, command=send_email_wrapper).place(relx=0.5, rely=0.9, anchor=CENTER)
    except Exception as e:
        messagebox.showerror("encryption", f"Encryption failed: {str(e)}")
```
- encrypt(): Handles the encryption process, including validating the password, checking its strength, padding the message, and encrypting it using AES in CBC mode. Displays the encrypted message in a new window.

## Decryption Function
The Decryption Function is responsible for decrypting encrypted messages using the AES algorithm. It verifies the provided password and ensures that the input message is not empty. Upon successful validation, the function decodes the base64-encoded message, extracts the initialization vector (IV), and decrypts the message using the provided password and IV. After decryption, it removes any padding added during encryption and displays the decrypted message in a graphical user interface for the user's convenience. Any decryption failures are appropriately handled and reported to the user.

``` python
def decrypt():
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
```
- decrypt(): Handles the decryption process, including validating the password, decoding the base64 encoded message, unpadding the message, and decrypting it using AES in CBC mode. Displays the decrypted message in a new window.

## Send Email Function
The Send Email Function facilitates the secure transmission of encrypted messages via email. It constructs an email content template containing the encrypted message and opens the default email client with the pre-filled content. This allows users to easily share encrypted messages with intended recipients using their preferred email service.

```python
def send_email(encrypted_message):
    email_content = f"Beginn der verschlüsselten Nachricht: \n\n{encrypted_message}"
    webbrowser.open('mailto:?subject=Encrypted%20Message&body=' + email_content)
```
- send_email(encrypted_message): Opens the default email client with the encrypted message pre-filled in the email body.

## Send Email Function
The Send Email Function facilitates the seamless transmission of encrypted messages via email. It composes an email content template containing the encrypted message and launches the default email client with the pre-filled content. This streamlines the process for users to share encrypted messages with their intended recipients using their preferred email service.

```python
def send_email(encrypted_message):
    email_content = f"Beginn der verschlüsselten Nachricht: \n\n{encrypted_message}"
    webbrowser.open('mailto:?subject=Encrypted%20Message&body=' + email_content)
```
- send_email(encrypted_message): Opens the default email client with the encrypted message pre-filled in the email body.

## Update Password Strength Function
The Update Password Strength Function dynamically evaluates the strength of a user-provided password and provides immediate feedback. By assessing various criteria such as length, character diversity, and the inclusion of special characters, it dynamically updates the user interface to reflect the current password strength status. This interactive feature assists users in creating robust and secure passwords for encrypting their messages, enhancing overall data security.

```python
def update_password_strength():
    password = code.get()
    strength_feedback = check_password_strength(password)
    if strength_feedback == "Die Schlüsselstärke ist ausreichend.":
        strength_label.config(text="Schlüsselstärke: Stark", fg="green")
    else:
        strength_label.config(text=strength_feedback, fg="red")
```
- update_password_strength(): Checks the password strength and updates the label with feedback.

## Toggle Key Visibility Function
The Toggle Key Visibility Function enables users to toggle the visibility of the password they input. By clicking on a designated button, the function alternates between displaying and hiding the characters entered in the password field. This feature enhances user convenience and security, allowing users to view or conceal their passwords as needed while entering sensitive information.

```python
def toggle_key_visibility():
    global show_key_icon
    if key_entry.cget('show') == '*':
        key_entry.config(show='')
        show_key_icon = hide_key_image
    else:
        key_entry.config(show='*')
        show_key_icon = show_key_image
    show_hide_key_button.config(image=show_key_icon)
```
- toggle_key_visibility(): Toggles the visibility of the key entry field between hidden and visible.

## Main Screen Function
The Main Screen Function initializes the graphical user interface (GUI) of the application. It sets up the main window dimensions, adds text input fields for messages and passwords, and includes buttons for encryption, decryption, and resetting. Additionally, it provides functionality for toggling key visibility and updating password strength feedback. This function serves as the central control point for user interaction, enabling seamless encryption and decryption processes within a user-friendly interface.

```python
def main_screen():
    global screen
    global code
    global text1
    global strength_label
    global show_key_image
    global hide_key_image
    global show_key_icon
    global key_entry
    global show_hide_key_button

    screen = Tk()
    screen.geometry("390x440")

    # Icon
    image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Secret Messenger")

    def reset():
        code.set("")
        text1.delete(1.0, END)

    Label(text="Text oder Chiffre hier eingeben:", fg="black", font=('calibri', 13)).place(x=10, y=10)
    text1 = Text(font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=40, width=345, height=100)

    Label(text="Geheimer Schlüssel:", fg="black", font=("calibri", 13)).place(x=10, y=170)

    code = StringVar()
    key_entry = Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*")
    key_entry.place(x=10, y=200)
    
    # Define images for showing and hiding key
    show_key_image = PhotoImage(file="img/show_password.png")
    hide_key_image = PhotoImage(file="img/hide_password.png")
    
    # Button to toggle key visibility
    show_key_icon = show_key_image
    show_hide_key_button = Button(screen, image=show_key_icon, bd=0, command=toggle_key_visibility)
    show_hide_key_button.place(x=355, y=210
```