from tkinter import *
from tkinter import messagebox, Toplevel, CENTER, END, GROOVE, WORD, filedialog
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import webbrowser
import qrcode
from PIL import ImageTk
import io

BLOCK_SIZE = 16  # Padding for AES (should be 16 bytes)

def pad(s):
    padding_length = BLOCK_SIZE - len(s) % BLOCK_SIZE
    padding = chr(padding_length).encode()
    return s + padding * padding_length

def unpad(s):
    padding_length = s[-1]
    return s[:-padding_length]

def get_key(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

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

        def send_email_wrapper():
            send_email(encrypted_message)
        
        def copy_to_clipboard():
            text = text2.get(1.0, END)
            screen.clipboard_clear()
            screen.clipboard_append(text)
            screen.update()
            messagebox.showinfo("Information", "Text in die Zwischenablage kopiert")
        
        def show_qr_code():
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
            
            Button(qr_window, text="QR Code speichern", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=lambda: save_image_to_file(qr_image)).pack()

        def generate_qr_code(message):
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(message)
            qr.make(fit=True)
            return qr.make_image(fill='black', back_color='white')

        def save_image_to_file(image):
            # Öffnen Sie den Datei-Dialog, um den Speicherort zu wählen
            file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if file_path:
                image.save(file_path)
                messagebox.showinfo("Information", "QR Code gespeichert")
        
        def copy_image_to_clipboard(image):
            # Erstellen Sie ein in-memory Date-like Objekt
            image_buffer = io.BytesIO()
            
            # Speichern Sie das Bild im PNG-Format in den Buffer
            image.save(image_buffer, format="PNG")
            image_buffer.seek(0)

            # Kopieren Sie das Bild in die Zwischenablage
            screen1.clipboard_clear()
            screen1.clipboard_append(image_buffer.getvalue(), type='image/png')
            screen1.update()
            messagebox.showinfo("Information", "QR Code in die Zwischenablage kopiert")

        Button(screen1, text="Kopieren", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=copy_to_clipboard).place(relx=0.15, rely=0.9, anchor=CENTER)
        Button(screen1, text="QR Code", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=show_qr_code).place(relx=0.50, rely=0.9, anchor=CENTER)
        Button(screen1, text="per Mail", height="2", width=15, bg="#1089ff", fg="white", bd=0, command=send_email_wrapper).place(relx=0.85, rely=0.9, anchor=CENTER)
    except Exception as e:
        messagebox.showerror("encryption", f"Encryption failed: {str(e)}")


def decrypt():
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

def send_email(encrypted_message):
    email_content = f"Beginn der verschlüsselten Nachricht: \n\n{encrypted_message}"
    webbrowser.open('mailto:?subject=Encrypted%20Message&body=' + email_content)


def update_password_strength():
    password = code.get()
    strength_feedback = check_password_strength(password)
    if strength_feedback == "Die Schlüsselstärke ist ausreichend.":
        strength_label.config(text="Schlüsselstärke: Stark", fg="green")
    else:
        strength_label.config(text=strength_feedback, fg="red")

def toggle_key_visibility():
    global show_key_icon
    if key_entry.cget('show') == '*':
        key_entry.config(show='')
        show_key_icon = hide_key_image
    else:
        key_entry.config(show='*')
        show_key_icon = show_key_image
    show_hide_key_button.config(image=show_key_icon)

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
