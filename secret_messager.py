from tkinter import *
from tkinter import messagebox, Toplevel, Label, PhotoImage, ttk, CENTER, END, GROOVE, WORD, filedialog, Button
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from functools import partial
from PIL import ImageTk
import base64
import webbrowser
import qrcode
import random
import string
import tempfile
import urllib.parse

BLOCK_SIZE = 16  # Padding for AES (should be 16 bytes)

def pad(s):
    """
    Pads the input string `s` with the appropriate number of padding characters
    to make its length a multiple of `BLOCK_SIZE`. The padding characters are
    created by repeating the character with value `padding_length`. Returns the
    padded string.

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
    Removes the padding from the input string `s` using the PKCS#7 padding scheme.
    
    Parameters:
        s (bytes): The input string to be unpadded.
    
    Returns:
        bytes: The unpadded string.
    """
    padding_length = s[-1]
    return s[:-padding_length]

def get_key(password):
    """
    Generates a key based on the input password.

    Parameters:
        password (str): The password used to generate the key.

    Returns:
        bytes: The key generated from the password.
    """
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def check_password_strength(password):
    """
    Check the strength of a password.

    This function checks the strength of a password based on the following criteria:
    - The password must be at least 8 characters long.
    - The password must contain at least one uppercase letter and one lowercase letter.
    - The password must contain at least one digit.
    - The password must contain at least one special character.

    Parameters:
        password (str): The password to be checked.

    Returns:
        str: A message indicating the strength of the password. If the password meets all the criteria, the message will be "Die Schlüsselstärke ist ausreichend". If the password is too short, the message will be "Schlüssel ist zu kurz. Mindestens 8 Zeichen verwenden." If the password does not contain at least one uppercase letter and one lowercase letter, the message will be "Mindestens ein Groß- und Kleinbuchstaben verwenden." If the password does not contain at least one digit, the message will be "Mindestens eine Ziffer verwenden." If the password does not contain at least one special character, the message will be "Mindestens ein Sonderzeichen verwenden."
    """
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

# Funktion zur zufälligen Generierung eines Passworts
def generate_random_key():
    """
    A function that generates a random key by combining uppercase letters, lowercase letters,
    punctuation characters, digits, and a mix of them to reach a minimum length. It shuffles the characters
    randomly and converts the list into a string. If the generated key is at least 8 characters long,
    it is returned.
    """
    while True:
        password = []
        password.append(random.choice(string.ascii_uppercase))
        password.append(random.choice(string.ascii_lowercase))
        password.append(random.choice(string.punctuation))
        password.append(random.choice(string.digits))
        password.append(random.choice(string.ascii_letters))

        # Füge zufällige Zeichen hinzu, um die Mindestlänge zu erreichen
        password.extend(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.ascii_letters + string.digits + string.punctuation, k=random.randint(5, 13)))

        # Mische die Zeichen zufällig
        random.shuffle(password)
        
        # Konvertiere die Liste in einen String
        password = ''.join(password)

        if len(password) >= 8:
            return password

def on_double_cklick(event):
    """
    Handles the event when a double click occurs on a treeview item.

    Args:
        event (tkinter.Event): The event object representing the double click event.

    Returns:
        None

    This function retrieves the focused item from the treeview and extracts its values. It then retrieves the first value (the key) and inserts it into the `key_entry` widget. Finally, it destroys the `screen3` window.
    """
    item = tree.focus()
    if item:
        values = tree.item(item, "values")
        key = values[0]
        key_entry.delete(0, END)
        key_entry.insert(END, key)
        screen3.destroy()

def save_image_to_file_and_send_email(qr_image):
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if file_path:
        try:
            qr_image.save(file_path)
            print(f"Image saved to {file_path}")
            messagebox.showinfo("Information", "QR Code gespeichert")

            # Kodieren des Dateipfads
            encoded_file_path = urllib.parse.quote(file_path)
            subject = urllib.parse.quote("QR Code Attachment")
            body = urllib.parse.quote("Anbei ein QR-Code.")

            # Öffnen des Standard-E-Mail-Programms mit dem QR-Code als Anhang
            webbrowser.open(f'mailto:?subject={subject}&body={body}&attachment="{encoded_file_path}"')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save QR Code: {str(e)}")
    else:
        print("No file selected")

def encrypt():
    """
    Encrypts a message using a password and displays the encrypted message in a new window.
    The function takes no parameters.

    Returns:
        None.

    This function retrieves the password from the `code` widget and checks its strength using the
    `check_password_strength` function. If the password is not strong enough, a warning message is
    displayed and the function returns. If the password is strong enough, the function proceeds to
    encrypt the message using the Advanced Encryption Standard (AES) algorithm in CBC mode.
    The encrypted message is then displayed in a new window along with buttons to copy the encrypted
    message to the clipboard, generate a QR code, and send the encrypted message via email.
    The function uses the `generate_qr_code` function to generate a QR code from the encrypted message
    and the `save_image_to_file` function to save the QR code to a file. The function also uses the
    `send_email_with_attachment` function to send the encrypted message via email with the QR code
    """
    
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
    
    image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
    screen1.iconphoto(False, image_icon)

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

        def send_email_wrapper(message_type, qr_image=None):
            """
            Sends an email based on the given message type and optional QR image attachment.

            Args:
                message_type (str): The type of message to send. Must be either 'encrypted' or 'qr_code'.
                qr_image (PIL.Image.Image, optional): The QR image to attach to the email. Only required if message_type is 'qr_code'.

            Returns:
                None

            This function opens a web browser to send an email. If message_type is 'encrypted', it creates an email content string with the encrypted message and opens a mailto link with the subject 'Encrypted Message' and the email content. If message_type is 'qr_code' and qr_image is not None, it creates an email content string with the message 'Anbei ein QR-Code' and calls the send_email_with_attachment function to send the email with the QR image attachment.
            """
            if message_type == 'encrypted':
                email_content = f"----- Beginn der verschlüsselten Nachricht ----- \n \n{encrypted_message}"
                webbrowser.open('mailto:?subject=Encrypted%20Message&body=' + urllib.parse.quote(email_content))
            elif message_type == 'qr_code' and qr_image is not None:
                email_content = f"Anbei ein QR-Code."
                send_email_with_attachment(qr_image, email_content)
        
        def copy_to_clipboard():
            """
            Copies the text from a Text widget to the clipboard and shows an information message.
            """
            text = text2.get(1.0, END)
            screen.clipboard_clear()
            screen.clipboard_append(text)
            screen.update()
            messagebox.showinfo("Information", "Text in die Zwischenablage kopiert")
        
        def show_qr_code():
            """
            Displays a QR code in a new window with buttons to send the QR code via email or save it to a file.

            This function checks if an encrypted message is available to generate the QR code. If not, it shows an error message and returns. If an encrypted message is available, it generates a QR code using the `generate_qr_code` function and creates a new window titled "QR Code" with a size of 400x420 pixels and a background color of "#ed3833". The QR code image is displayed in a label within the new window.

            The function also creates two buttons within the new window. The first button, labeled "per Mail", sends the QR code via email using the `send_email_wrapper` function with the message type 'qr_code' and the QR code image as parameters. The second button, labeled "QR Code speichern", saves the QR code image to a file using the `save_image_to_file` function.

            The buttons are placed at the bottom of the new window with a relative x-coordinate of 0.25 and 0.75 respectively, and an anchor of CENTER
            """
            if not encrypted_message:
                messagebox.showerror("Error", "No encrypted message to generate QR code.")
                return
            
            qr_image = generate_qr_code(encrypted_message)

            qr_window = Toplevel(screen1)
            qr_window.title("QR Code")
            qr_window.geometry("400x420")
            qr_window.configure(bg="#ed3833")
            
            image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
            qr_window.iconphoto(False, image_icon)
            
            qr_photo = ImageTk.PhotoImage(qr_image)

            qr_label = Label(qr_window, image=qr_photo)
            qr_label.image = qr_photo
            qr_label.pack()

            
            # Erstellen der Buttons
            button1 = Button(qr_window, text="per Mail", height=2, width=15, bg="#1089ff", fg="white", bd=0, command=lambda: save_image_to_file_and_send_email(qr_image))
            button2 = Button(qr_window, text="QR Code speichern", height=2, width=15, bg="#1089ff", fg="white", bd=0, command=lambda: save_image_to_file(qr_image))

            # Platzierung der Buttons
            button1.place(relx=0.25, rely=0.93, anchor=CENTER)
            button2.place(relx=0.75, rely=0.93, anchor=CENTER)

        def generate_qr_code(message):
            """
            Generates a QR code image based on the given message.

            Parameters:
                message (str): The message to be encoded in the QR code.

            Returns:
                PIL.Image.Image: The generated QR code image.

            This function creates a QR code object with the specified version, error correction level, box size, and border. 
            It then adds the given message to the QR code object and generates the QR code image. 
            The generated image is returned as a PIL.Image.Image object.

            Example usage:
            ```
            qr_image = generate_qr_code("Hello, World!")
            ```
            """
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            
            qr.add_data(message)
            qr.make(fit=True)
            qr_image = qr.make_image(fill='black', back_color='white')
            return qr_image

        def save_image_to_file(qr_image):
            """
            Saves the given QR code image to a file using a file dialog.

            Args:
                qr_image (PIL.Image.Image): The QR code image to be saved.

            Returns:
                None

            This function opens a file dialog to allow the user to select a location to save the QR code image. 
            If a file path is selected, the QR code image is saved to that location with a .png extension. 
            After the image is saved, a confirmation message is displayed using a messagebox. 
            If no file path is selected, a message is printed indicating that no image was saved.
            """
            file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if file_path:
                qr_image.save(file_path)
                print(f"Image saved to {file_path}")
                messagebox.showinfo("Information", "QR Code gespeichert")
            else:
                print("No image to save")

        def send_email_with_attachment(qr_image, email_content):
            """
            Sends an email with a QR code attachment using the standard email client.

            Args:
                qr_image (PIL.Image.Image): The QR code image to be attached to the email.
                email_content (str): The content of the email.

            Returns:
                None

            This function saves the QR code image to a temporary file with a .png extension.
            The file path is then encoded using URL encoding.
            The subject and body of the email are also encoded using URL encoding.
            The standard email client is then opened with the encoded subject, body, and attachment file path.
            If an exception occurs during the process, an error message is displayed using a messagebox.

            Example usage:
                send_email_with_attachment(qr_image, "Hello, this is the email content.")
            """
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp_file:
                    temp_file_path = temp_file.name
                    qr_image.save(temp_file_path)

                # Kodieren des Dateipfads
                encoded_file_path = urllib.parse.quote(temp_file_path)
                subject = urllib.parse.quote("QR Code Attachment")
                body = urllib.parse.quote(email_content)

                # Öffnet das Standard-E-Mail-Programm mit dem QR-Code als Anhang
                webbrowser.open(f'mailto:?subject={subject}&body={body}&attachment="{encoded_file_path}"')
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save QR Code: {str(e)}")

        Button(screen1, text="Kopieren", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=copy_to_clipboard).place(relx=0.15, rely=0.9, anchor=CENTER)
        Button(screen1, text="QR Code", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=show_qr_code).place(relx=0.50, rely=0.9, anchor=CENTER)
        Button(screen1, text="per Mail", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=partial(send_email_wrapper, 'encrypted')).place(relx=0.85, rely=0.9, anchor=CENTER)
    except Exception as e:
        messagebox.showerror("encryption", f"Encryption failed: {str(e)}")


def decrypt():
    """
    Decrypts the message entered in the text box using the password provided in the code entry box.
    
    This function prompts the user to enter a password in the code entry box. If the password is empty, an error message is displayed and the function returns. Otherwise, a new window is created for decryption. The message entered in the text box is retrieved and stripped of leading and trailing whitespace. If the message is empty, an error message is displayed and the function returns. Otherwise, the decryption process begins. The password is used to generate a key, which is then used to decrypt the message. The decrypted message is displayed in the new window. If an error occurs during decryption, an error message is displayed.
    
    Parameters:
    None
    
    Returns:
    None
    """
    password = code.get()
    if password == "":
        messagebox.showerror("encryption", "Schlüssel eingeben")
        return

    screen2 = Toplevel(screen)
    screen2.title("decryption")
    screen2.geometry("400x250")
    screen2.configure(bg="#00bd56")

    image_icon = PhotoImage(file="img/kisspng-key-icon-magic-keys.png")
    screen2.iconphoto(False, image_icon)

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

def open_history():
    """
    Function to open a history window and create a Treeview table with columns, headings, and entries. 
    Binds double-click events for copying and displaying context menus.
    """
    global tree, text1, screen3
    
    screen3 = Toplevel()
    screen3.title("Vorschläge")
    screen3.geometry("440x230")

    # Erstellen einer Tabelle (Treeview) in screen3
    tree = ttk.Treeview(screen3, columns=("Key", "Strength"), show="headings")
    
    # Überschriften der Spalten definieren
    tree.heading("Key", text="Schlüssel", anchor="w")
    tree.heading("Strength", text="Stärke", anchor="w")
    
    # Einträge in die Tabelle einfügen
    for i in range(1, 21):  # 20 Einträge erstellen
        random_key = generate_random_key()
        strength = check_password_strength(random_key)
        tree.insert("", END, iid=i, text=str(i), values=(random_key, strength))
        
    # Doppelklick-Ereignisbindung für die Treeview
    tree.bind("<Double-1>", on_double_cklick)
    
    # Funktion zur Kopierfähigkeit der Zellen in der Spalte "Schlüssel"
    def copy_selection():
        """
        Copies the selected item from the Treeview widget to the clipboard.

        This function retrieves the currently selected item in the Treeview widget and copies its value to the clipboard. The selected item is identified by calling the `focus()` method on the Treeview widget. If a selected item is found, the function retrieves the value of the first column of the item using the `item()` method with the `values` parameter set to 0. The value is then cleared from the clipboard using the `clipboard_clear()` method and appended to the clipboard using the `clipboard_append()` method.

        Parameters:
            None

        Returns:
            None
        """
        selected_item = tree.focus()
        if selected_item:
            item_text = tree.item(selected_item)["values"][0]
            screen3.clipboard_clear()
            screen3.clipboard_append(item_text)

    # Kontextmenü für Kopieren hinzufügen
    tree.bind("<Button-3>", lambda event: tree.focus() or tree.selection_set(tree.identify_row(event.y)) or tree.selection_add(tree.identify_row(event.y)))
    popup_menu = Menu(screen3, tearoff=0)
    popup_menu.add_command(label="Kopieren", command=copy_selection)
    
    def popup(event):
        """
        Display a popup menu at the coordinates specified by the given event.

        Args:
            event (Event): The event object that triggered the popup menu.

        Returns:
            None
        """
        popup_menu.post(event.x_root, event.y_root)
    
    tree.bind("<Button-3>", popup)

    # Doppelklick-Ereignisbindung für die Treeview
    tree.bind("<Double-1>", on_double_cklick)
    
    # Tabelle in das Fenster einfügen
    tree.pack(expand=True, fill=BOTH)
    
    # Textfeld für die Übernahme des Schlüssels per Doppelklick
    key_entry = Text(screen3, font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    key_entry.pack(expand=True, fill=BOTH)


def update_password_strength():
    """
    Updates the password strength label based on the current password.

    This function retrieves the current password from the 'code' variable and
    calls the 'check_password_strength' function to determine the password
    strength. If the password strength is deemed sufficient, the label is
    updated with the text "Schlüsselstärke: Stark" and the color is set to green.
    Otherwise, the label is updated with the password strength feedback and
    the color is set to red.

    Parameters:
        None

    Returns:
        None
    """
    password = code.get()
    strength_feedback = check_password_strength(password)
    if strength_feedback == "Die Schlüsselstärke ist ausreichend.":
        strength_label.config(text="Schlüsselstärke: Stark", fg="green")
    else:
        strength_label.config(text=strength_feedback, fg="red")

def toggle_key_visibility():
    """
    Toggles the visibility of the key in the key_entry field.

    This function checks the current visibility setting of the key_entry field
    using the 'show' attribute. If the key is currently hidden (indicated by
    the '*' character), it is made visible by setting the 'show' attribute to
    an empty string. The show_key_icon variable is updated accordingly. If the
    key is currently visible, it is hidden by setting the 'show' attribute to
    '*'. The show_key_icon variable is updated accordingly. Finally, the
    show_hide_key_button is updated with the new image.

    Parameters:
        None

    Returns:
        None
    """
    global show_key_icon
    if key_entry.cget('show') == '*':
        key_entry.config(show='')
        show_key_icon = hide_key_image
    else:
        key_entry.config(show='*')
        show_key_icon = show_key_image
    show_hide_key_button.config(image=show_key_icon)

def main_screen():
    """
    Initializes the main screen of the Secret Messenger application.

    This function creates the main window of the application and sets its
    dimensions. It also sets the window icon and title.

    The function creates several GUI elements, including labels, text fields,
    buttons, and images. These elements are used to display messages, passwords,
    and buttons for encryption, decryption, and resetting.

    The function also includes functionality for toggling key visibility and
    updating password strength feedback.

    Parameters:
        None

    Returns:
        None
    """
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
        """
        Resets the code and text1 variables to their initial state.

        This function clears the contents of the code variable and deletes all text from the text1 widget.

        Parameters:
            None

        Returns:
            None
        """
        code.set("")
        text1.delete(1.0, END)

    Label(text="Text oder Chiffre hier eingeben:", fg="black", font=('calibri', 13)).place(x=10, y=10)
    text1 = Text(font=("Roboto", 10), bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=40, width=345, height=100)

    Label(text="Geheimer Schlüssel:", fg="black", font=("calibri", 13)).place(x=10, y=170)
    Button(screen, text="Vorschläge", height="1", width=9, bg="#1089ff", fg="white", bd=0, command=open_history).place(x=278, y=170)


    code = StringVar()
    key_entry = Entry(textvariable=code, width=37, bd=0, font=("arial", 13), show="*")
    key_entry.place(x=10, y=200, height=30)

    # Define images for showing and hiding key
    show_key_image = PhotoImage(file="img/show_password.png")
    hide_key_image = PhotoImage(file="img/hide_password.png")

    # Button to toggle key visibility
    show_key_icon = show_key_image
    show_hide_key_button = Button(screen, image=show_key_icon, bd=0, command=toggle_key_visibility)
    show_hide_key_button.place(x=355, y=210)

    # Add label for password strength feedback
    strength_label = Label(text="Schlüsselstärke: ", fg="black", font=("calibri", 11))
    strength_label.place(x=10, y=255)

    # Add button to update password strength feedback
    Button(text="Check Password Strength", height="1", width=23, bg="#1089ff", fg="white", bd=0, command=update_password_strength).place(x=10, y=280)

    # Add button with icon
    decrypt_icon = PhotoImage(file="img/decrypt_icon.png")
    Button(screen, text="VERSCHLÜSSELN", image=decrypt_icon, compound=LEFT, padx=10, pady=10, height="22", width=153, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=330)

    encrypt_icon = PhotoImage(file="img/encrypt_icon.png")
    Button(screen, text="ENTSCHLÜSSELN", image=encrypt_icon, compound=LEFT, padx=10, pady=10, height="22", width=152, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=330)

    Button(screen, text="RESET", height="2", width=51, bg="#6a6a6a", fg="white", bd=0, command=reset).place(x=10, y=380)

    screen.mainloop()

main_screen()
