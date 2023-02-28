# pip install pybase

from tkinter import *
from tkinter import messagebox
import base64 # encryption and decryption
import os # operating system functionality

def decrypt():
    
    password=code.get()
    
    if password=="1234":
        screen2=Toplevel(screen)
        screen2.title("decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")
        
        message=text1.get(1.0,END)
        decode_message=message.encode("ascii")
        base64_bytes=base65.b64decode(decode_message)
        decrypt=base64_bytes.decode("ascii")
        
        
        Label(screen2,text="DECRYPT",font="arial",fg="white",bg="#00bd56").place(x=10,y=0)
        text2=Text(screen2,font="Rpbote 10",bg="white",relief=GROOVE,wrap=WORD,bd=0)
        text2.place(x=10,y=40,width=380,height=150)
        
        text2.insert(END,decryt)
        
    elif password=="":
        messagebox.showerror("encryption", "Input Password")
        
    elif password !="1234":
        messagebox.showerror("encryption", "Invalid Password")

def encrypt():
    '''Verschlüsselt die Nachricht einem definierten Schlüssel (1234)'''
    password=code.get()
    
    if password=="1234":
        screen1=Toplevel(screen)
        screen1.title("encryption")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")
        
        message=text1.get(1.0,END)
        encode_message=message.encode("ascii")
        base64_bytes=base65.b64encode(encode_message)
        encrypt=base64_bytes.decode("ascii")
        
        Label(screen1,text="ENCRYPT",font="arial",fg="white",bg="#ed3833").place(x=10,y=0)
        text2=Text(screen1,font="Rpbote 10",bg="white",relief=GROOVE,wrap=WORD,bd=0)
        text2.place(x=10,y=40,width=380,height=150)
        
        text2.insert(END,encryt)
        
    elif password=="":
        messagebox.showerror("encryption", "Input Password")
        
    elif password !="1234":
        messagebox.showerror("encryption", "Invalid Password")


def main_screen():
    '''Hauptscreen'''
    global screen
    global code
    global text1
    
    screen=Tk()
    screen.geometry("375x398")
    
    #icon
    image_icon=PhotoImage(file="kisspng-key-icon-magic-keys.png")
    screen.iconphoto(False,image_icon)
    screen.title("Secret Messager")
    
    def reset():
        code.set("")
        text.delete(1.0,END)
    
    Label(text="Text zur Ver- und Entschlüsselung:",fg="black",font=('calibri',13)).place(x=10,y=10)
    text1=Text(font='Robote 20',bg="white",relief=GROOVE,wrap=WORD,bd=0)
    text1.place(x=10,y=50,width=35,height=100)
    
    Label(text="Geheimer Schlüssel für die Ver- und Entschlüsselung:",fg="black",font=("calibri",13)).place(x=10,y=170)
    
    code=StringVar()
    Entry(textvariable=code,width=19,bd=0,font=("arial",25),show="*").place(x=10,y=200)
    
    Button(text="ENCRYPT",height="2",width=23,bg="#ed3833",fg="white",bd=0,command=encrypt).place(x=10,y=250)
    Button(text="DECRYPT",height="2",width=23,bg="#00bd56",fg="white",bd=0,command=decrypt).place(x=200,y=250)
    Button(text="RESET",height="2",width=50,bg="#1089ff",fg="white",bd=0,command=reset).place(x=10,y=300)
    
    screen.mainloop ()

main_screen()
