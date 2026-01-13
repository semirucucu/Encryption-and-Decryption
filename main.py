import base64
import hashlib
import tkinter
from tkinter import messagebox

from cryptography.fernet import Fernet

window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=500,height=800)

def EncryptButton():
    masterKey = entryTextOfMasterKey.get()
    secret = entryTextOfSecret.get("1.0",tkinter.END)
    title = entryTextOfTitle.get()

    if (masterKey != "" and secret != "" and title != ""):

        key = base64.urlsafe_b64encode(
            hashlib.sha256(masterKey.encode()).digest()
        )

        fernet = Fernet(key)

        encrypted = fernet.encrypt(secret.encode())

        with open("secrets.txt", "a", encoding="utf-8") as file:
            file.write(title + "\n" + encrypted.decode() + "\n\n")

        entryTextOfSecret.delete("1.0",tkinter.END)
        entryTextOfMasterKey.delete(0,tkinter.END)
        entryTextOfTitle.delete(0,tkinter.END)

    else:
        messagebox.showinfo("Warning","Don't let the textboxes empty!")

def DecryptButton():
    secret = entryTextOfSecret.get("1.0", tkinter.END)
    masterKey = entryTextOfMasterKey.get()

    if (masterKey != "" and secret != ""):

        key = base64.urlsafe_b64encode(
            hashlib.sha256(masterKey.encode()).digest()
        )

        fernet = Fernet(key)

        try:
            encryptedBytes = secret.encode()
            decrypted = fernet.decrypt(encryptedBytes)

            entryTextOfSecret.delete("1.0",tkinter.END)
            entryTextOfSecret.insert("1.0",decrypted.decode())
        except:
            fake_message = fernet.encrypt(b"ACCESS DENIED").decode()

            entryTextOfSecret.delete("1.0", tkinter.END)
            entryTextOfSecret.insert("1.0", fake_message)
    else:
        messagebox.showinfo("Warning","Enter your encrypted text and master key!")


#resim
imageOfTopSecret = tkinter.PhotoImage(file="topsecret.png")
imageOfTopSecret = imageOfTopSecret.subsample(15,15)

imgLabel = tkinter.Label(window, image=imageOfTopSecret)
imgLabel.pack()

#title
tkinter.Label(text="Enter your title", font=("Arial", 16, "bold")).pack()

entryTextOfTitle = tkinter.Entry(font=("Arial",14,"normal"), width=25)
entryTextOfTitle.pack()

#padding için boş label
tkinter.Label(text="").pack(pady=10)

#mesaj
tkinter.Label(text="Enter your secret", font=("Arial",16, "bold")).pack()

entryTextOfSecret = tkinter.Text(window, font=("Arial",14,"normal"), height=15, width=25)
entryTextOfSecret.pack()

#padding için boş label
tkinter.Label(text="").pack(pady=10)

#master key
tkinter.Label(text="Enter master key", font=("Arial",16,"bold")).pack()

entryTextOfMasterKey = tkinter.Entry(font=("Arial",14,"normal"), width=25)
entryTextOfMasterKey.pack()


#save and encrypt buton
saveAndEncryptButton = tkinter.Button(text="Save & Encrypt",font=("Arial", 14, "normal"), command=EncryptButton)
saveAndEncryptButton.pack(pady=10)

#decrypt buton
saveAndEncryptButton = tkinter.Button(text="Decrypt",font=("Arial", 14, "normal"),command=DecryptButton)
saveAndEncryptButton.pack(pady=10)

#padding için boş label
tkinter.Label(text="").pack(pady=10)

window.mainloop()