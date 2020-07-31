# Import module for tkinter GUI
from tkinter import *
import tkinter as tk
# Import module for AES Symmetrical Cryptography 
from cryptography.fernet import Fernet
# Import module for RSA Asymmetrical Cryptography
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import binascii
#import rsa # Module for RSA Asymmetric Cryptography


# Create new variable to call tkinter window
root = Tk()
# Set title for the Python GUI program
root.title("Hybrid Cryptography Program")
# Set the size of the tkinter window
root.geometry('500x375')
# Set the window so it cannot be resizable
root.resizable(0,0)


# Functions
# Function to call Session Key Exchange Menu
def menu_SKE():
    menu_SKE = Toplevel(root)
    menu_SKE.title("Hybrid Cryptography Program - Session Key Exchange")
    menu_SKE.geometry("500x500")
    menu_SKE.resizable(0,0)
    SKELabel = Label(menu_SKE, text="Session Key Exchange Menu",
                     font="Helvetica, 20").pack(pady=20)
    menu_GenSK_Button = Button(menu_SKE, text="Generate AES Session Key",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_GenSK).pack(pady=20)
    menu_GenPPK_Button = Button(menu_SKE, text="Generate Public & Private Key",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_GenPPK).pack(pady=20)
    menu_EnccSK_Button = Button(menu_SKE, text="Encrypt Session Key",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_EncSK).pack(pady=20)
    menu_DecSK_Button = Button(menu_SKE, text="Decrypt Session Key",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_DecSK).pack(pady=20)




# Function to call Generate Session Key Menu
def menu_GenSK():
    menu_GenSK = Toplevel(root)
    menu_GenSK.title("Hybrid Cryptography Program - Generate Session Key")
    menu_GenSK.geometry("550x300")
    menu_GenSK.resizable(0,0)

    # Function to Generate random AES Session Key
    def generate_session_key():
        # Generate random 128-bit AES Key in Bytes
        key = Fernet.generate_key()
        # Decode the generated key from Bytes into a String/UTF-8/ASCII
        decode_key = key.decode("utf-8")
        # Show the (Decoded Random Generated 128-bit) Key to the Entry
        GenSKEntry.delete(0, END)
        GenSKEntry.insert(0, decode_key)

    # Label for Generate Session Key Menu
    GenSKMenuLabel = Label(menu_GenSK, text="Generate Session Key Menu",
                           font="Helvetica, 25").pack(pady=20)

    # Button to generate Session Key
    GenSKButton = Button(menu_GenSK, text="Generate Session Key",
                         font="Helvetica, 15", width=30, height=1,
                         command=generate_session_key)
    GenSKButton.pack(pady=25)
    # Label for Generated Session Key Info
    GenSKLabel = Label(menu_GenSK, text="Generated Session Key:").pack(pady=10)
    # Entry to show the generated Session Key
    GenSKEntry = Entry(menu_GenSK, width=50)
    GenSKEntry.pack(pady=10)



# Function to call Generate Session Key Menu
def menu_GenPPK():
    menu_GenPPK = Toplevel(root)
    menu_GenPPK.title("Hybrid Cryptography Program - Generate Public & Private Key")
    menu_GenPPK.geometry("550x700")
    menu_GenPPK.resizable(0,0)

    # Function to generate Public & Private Key
    def generate_public_private_key():
        # Generate RSA Keys (1024-bit)
        keyPair = RSA.generate(1024)
        pubKey = keyPair.publickey()
        pubKeyPEM = pubKey.exportKey()
        # Decode the RSA Public Key from byte to ASCII
        pubKeyPEMDecode = (pubKeyPEM.decode('ascii'))
        # Text for generated RSA Public Key (in the Text Widget)
        GenPublicKeyText.delete('1.0', END)
        GenPublicKeyText.insert('1.0', pubKeyPEMDecode)

        privKeyPEM = keyPair.exportKey()
        # Decode the RSA Private Key
        privKeyPEMDecode = (privKeyPEM.decode('ascii'))

        # Text for generated RSA Private Key (in the Text Widget)
        GenPrivateKeyText.delete('1.0', END)
        GenPrivateKeyText.insert('1.0', privKeyPEMDecode)

    # Label for Generate Public & Private Key Menu
    GenPPKMenuLabel = Label(menu_GenPPK, text="Generate Public & Private Key Menu",
                           font="Helvetica, 25").pack(pady=20)
    # Button to Generate Public & Private Key
    GenPPKButton = Button(menu_GenPPK, text="Generate Public &  Private Key",
                         font="Helvetica, 15", width=30, height=1,
                         command=generate_public_private_key)
    GenPPKButton.pack(pady=25)
    # Label for Generated Public Key Info
    GenPublicKeyLabel = Label(menu_GenPPK, text="Generated Public Key:").pack(pady=10)
    # Text Widget for Generated Public Key
    GenPublicKeyText = Text(menu_GenPPK, width=65, height=6)
    GenPublicKeyText.pack(pady=10)
    # Label for Generated Private Key Info
    GenPrivateKeyLabel = Label(menu_GenPPK, text="Generated Private Key:").pack(pady=10)
    # Text Widget for Generated Public Key
    GenPrivateKeyText = Text(menu_GenPPK, width=65, height=15)
    GenPrivateKeyText.pack(pady=10)



# Function to call Generate Session Key Menu
def menu_EncSK():
    menu_EncSK = Toplevel(root)
    menu_EncSK.title("Hybrid Cryptography Program - Encrypt Session Key")
    menu_EncSK.geometry("550x600")
    menu_EncSK.resizable(0,0)
    EncSKLabel = Label(menu_EncSK, text="Encrypt Session Key",
                    font="Helvetica, 20").pack(pady=20)

    # Function to Encrypt Session Key
    def encrypt_session_key():
        # Create new variable to get the input from the "public_keyText" Text Widget and Session Key Entry
        ## Get the Session Key from the Entry Widget
        input_session_key = session_key.get()
        # Encode the Session Key from String to Bytes
        input_session_key_encode = input_session_key.encode()
        ## Get the Public Key from the Text Widget
        input_public_keyText = public_keyText.get('1.0', 'end-1c')
        # Import Key from the "input_public_keyText"
        recipient_key = RSA.import_key(input_public_keyText)        
        # To read the Public Key
        encryptor = PKCS1_OAEP.new(recipient_key)
        #print(encryptor)
        # To encrypt the Session Key
        encrypted = encryptor.encrypt(input_session_key_encode)
        # The Result of The Session Key Encryption is the "encrypted" in bytes
        print(encrypted)
        #print("Encrypted:")
        #print(encrypted)
        
        # hexlify the encrypted Session Key
        encryptedSKhex = binascii.hexlify(encrypted)
        print(encryptedSKhex)
        encryptedSKhex_decode = encryptedSKhex.decode('utf-8')
        print(encryptedSKhex_decode)
        # To show the encrypted Session Key
        encryptedSKText.delete('1.0', END)
        encryptedSKText.insert('1.0', encryptedSKhex_decode)

        '''
        # Decrypt test
        input_private_keyText = input("Enter Private Key: ")
        private_key = RSA.import_key(input_private_keyText)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted)
        '''
        

    
    # Label to enter the Session Key
    session_keyLabel = Label(menu_EncSK, text="Please enter the Session Key:").pack(pady=10)
    # Entry to enter the Session Key
    session_key = Entry(menu_EncSK, width=50)
    session_key.pack(pady=10)
    # Label to enter Public Key
    public_keyLabel = Label(menu_EncSK, text="Please enter the Public Key:").pack(pady=10)
    # Text Widget to enter the Public Key
    public_keyText = Text(menu_EncSK, width=50, height=7)
    public_keyText.pack(pady=10)
    # Button to encrypt the Session Key
    encryptSKButton = Button(menu_EncSK, text="Encrypt", font="Helvetica, 15",
                             width=20, height=2, command=encrypt_session_key)
    encryptSKButton.pack(pady=10)
    # Label to show the encrypted Session Key
    encSKLabel = Label(menu_EncSK, text="Encrypted Session Key:").pack()
    # Text Widget to show the encrypted Session Key
    encryptedSKText = Text(menu_EncSK, width=50, height=7)
    encryptedSKText.pack(pady=10)



# Function to call Generate Session Key Menu
def menu_DecSK():
    menu_DecSK = Toplevel(root)
    menu_DecSK.title("Hybrid Cryptography Program - Decrypt Session Key")
    menu_DecSK.geometry("550x700")
    menu_DecSK.resizable(0,0)
    DecSKLabel = Label(menu_DecSK, text="Decrypt Session Key",
                    font="Helvetica, 20").pack(pady=10)

    # Function to Decrypt Session Key
    def decrypt_session_key():
        # Create new variable to get the input from the "private_keyText" Text Widget and encrypted session key Text Widget
        # Input the UTF-8 Encrypted Hex Session Key
        input_encryptedSK = encryptedSKText.get('1.0', 'end-1c')
        # Input Private Key
        input_private_keyText = private_keyText.get('1.0', 'end-1c')
        # Encode UTF-8 Encrypted Hex Session Key to Bytes
        input_encryptedSK_encode = input_encryptedSK.encode()
        # unhexlify the decrypted Session Key
        decryptedSKunhex = binascii.unhexlify(input_encryptedSK_encode)
        print(decryptedSKunhex)
        # Import the Private Key
        private_key = RSA.import_key(input_private_keyText)
        # Encode Private Key
        #input_private_keyText_encode = input_private_keyText.encode()
        #print(private_key)
        

        
        # RSA Decryption
        decryptor = PKCS1_OAEP.new(private_key)
        decrypted = decryptor.decrypt(decryptedSKunhex)

        '''
        # hexlify the decrypted Session Key
        decryptedSKhex = binascii.hexlify(decrypted)
        '''

        # To show the result to the Text Widget
        decryptedSKText.delete('1.0', END)
        decryptedSKText.insert('1.0', decrypted)
        

    # Label to enter the Encrypted Session Key
    encryptedSKLabel = Label(menu_DecSK, text="Please enter the encrypted Session Key:").pack(pady=10)
    # Text Widget to enter the Encrypted Session Key
    encryptedSKText = Text(menu_DecSK, width=50, height=7)
    encryptedSKText.pack()
    # Label to enter the Private Key for Decryption
    private_keyLabel = Label(menu_DecSK, text="Please enter the Private Key:")
    private_keyLabel.pack()
    # Text Widget to enter the Private Key for decryption
    private_keyText = Text(menu_DecSK, width=50, height=10)
    private_keyText.pack(pady=10)
    # Button to Decrypt the Encrypted Session Key using the RSA Private Key
    decryptSKButton = Button(menu_DecSK, text="Decrypt", command=decrypt_session_key)
    decryptSKButton.pack()
    # Label to show the Decrypted Session Key
    DecSKLabel = Label(menu_DecSK, text="Decrypted Session Key:").pack(pady=10)
    # Text Widget to show the Decrypted Session Key
    decryptedSKText = Text(menu_DecSK, width=50, height=10)
    decryptedSKText.pack(pady=10)
    



# Function to Generate random AES Session Key
def generate_session_key():
    # Generate random 128-bit AES Key in Bytes
    key = Fernet.generate_key()
    # Decode the generated key from Bytes into a String/UTF-8/ASCII
    decode_key = key.decode("utf-8")
    # Show the (Decoded Random Generated 128-bit) Key to the Entry
    GenSKEntry.delete(0, END)
    GenSKEntry.insert(0, decode_key)

# Function to call Message Encryption & Decryption Menu
def menu_MED():
    menu_MED = Toplevel(root)
    menu_MED.title("Hybrid Cryptography Program - Message Encryption & Decryption")
    menu_MED.geometry("500x300")
    menu_MED.resizable(0,0)
    MEDLabel = Label(menu_MED, text="Message Encrypt & Decrypt Menu",
                     font="Helvetica, 20").pack(pady=20)
    menu_GenSK_Button = Button(menu_MED, text="Encrypt Message",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_ME).pack(pady=20)
    menu_GenPPK_Button = Button(menu_MED, text="Decrypt Message",
                               font="Helvetica, 15", width=35, height=2,
                               command=menu_MD).pack(pady=20)

# Function to call Message Encryption Menu
def menu_ME():
    menu_ME = Toplevel(root)
    menu_ME.title("Hybrid Cryptography Program - Message Encryption")
    menu_ME.geometry("500x600")
    menu_ME.resizable(0,0)
    MELabel = Label(menu_ME, text="Message Encryption",
                    font="Helvetica, 20").pack(pady=20)

    # Function to "Encrypt" the message
    def encrypt_message():
        # Create new variable to get the input from the "messageText" Text Widget and the Session Key Entry
        input_messageText = messageText.get('1.0', 'end-1c')
        input_session_key = session_key.get()
        # Encode the message into bytes
        input_messageText_encode = input_messageText.encode()
        input_session_key_encode = input_session_key.encode()
        # Call the Fernet Key
        cipher_suite = Fernet(input_session_key_encode)
        # Encrypt the message using the Session Key
        encrypt_messageText = cipher_suite.encrypt(input_messageText_encode)
        decode_encrypt_messageText = encrypt_messageText.decode("ascii")
        encryptedMsgText.delete('1.0', END)
        encryptedMsgText.insert('1.0', decode_encrypt_messageText)

    # Label to enter the Session Key
    session_keyLabel = Label(menu_ME, text="Please enter the Session Key:").pack(pady=10)
    # Entry to enter the Session Key
    session_key = Entry(menu_ME, width=50)
    session_key.pack(pady=10)
    # Label to enter Message
    messageLabel = Label(menu_ME, text="Please enter the message:").pack(pady=10)
    # Text Widget to enter Message
    messageText = Text(menu_ME, width=50, height=7)
    messageText.pack(pady=10)
    # Button to encrypt the message
    encryptMsgButton = Button(menu_ME, text="Encrypt", font="Helvetica, 15",
                              width=20, height=2, command=encrypt_message)
    encryptMsgButton.pack(pady=10)
    # Label to show the encrypted message
    encMessageLabel = Label(menu_ME, text="Encrypted message:").pack()
    # Text Widget to show the encrypted message
    encryptedMsgText = Text(menu_ME, width=50, height=7)
    encryptedMsgText.pack(pady=10)

# Function to call Message Decryption Menu
def menu_MD():
    menu_MD = Toplevel(root)
    menu_MD.title("Hybrid Cryptography Program - Message Encryption")
    menu_MD.geometry("500x600")
    menu_MD.resizable(0,0)
    MELabel = Label(menu_MD, text="Message Decryption",
                    font="Helvetica, 20").pack(pady=20)

    # Function to "Encrypt" the message
    def decrypt_message():
        # Create new variable to get the input from the "messageText" Text Widget and the Session Key Entry
        input_messageText = messageText.get('1.0', 'end-1c')
        input_session_key = session_key.get()
        # Encode the message into bytes
        input_messageText_encode = input_messageText.encode()
        input_session_key_encode = input_session_key.encode()
        # Call the Fernet Key
        cipher_suite = Fernet(input_session_key_encode)
        # Decrypt the message using the Session Key
        decrypt_messageText = cipher_suite.decrypt(input_messageText_encode)
        decode_encrypt_messageText = decrypt_messageText.decode("ascii")
        decryptedMsgText.delete('1.0', END)
        decryptedMsgText.insert('1.0', decode_encrypt_messageText)

    # Label to enter the Session Key
    session_keyLabel = Label(menu_MD, text="Please enter the Session Key:").pack(pady=10)
    # Entry to enter the Session Key
    session_key = Entry(menu_MD, width=50)
    session_key.pack(pady=10)
    # Label to enter encrypted Message
    messageLabel = Label(menu_MD, text="Please enter the encrypted message:").pack(pady=10)
    # Text Widget to enter encrypted Message
    messageText = Text(menu_MD, width=50, height=7)
    messageText.pack(pady=10)
    # Button to decrypt the message
    decryptMsgButton = Button(menu_MD, text="Decrypt", font="Helvetica, 15",
                              width=20, height=2, command=decrypt_message)
    decryptMsgButton.pack(pady=10)
    # Label to show the decrypted message
    decMessageLabel = Label(menu_MD, text="Decrypted message:").pack()
    # Text Widget to show the decrypted message
    decryptedMsgText = Text(menu_MD, width=50, height=7)
    decryptedMsgText.pack(pady=10)




# Main Menu
# Create new label
labelmenu = Label(root, text="Hybrid Cryptography Program Menu",
                  font="Helvetica, 20").pack(pady=25)

# Menu Button
SKEButton = Button(root, text="Session Key Exhange",
            font="Helvetica, 15", height=2, width=30,
            command=menu_SKE).pack(pady=10)
#SKEButton.pack(pady=10)

MEDButton = Button(root, text="Message Encryption & Decryption",
            font="Helvetica, 15", height=2, width=30,
            command=menu_MED).pack(pady=10)
#MEDButton.pack(pady=10)

# Quit Button
QuitButton = Button(root, text="Quit",
            font="Helvetica, 15", height=1, width=30,
            command=root.destroy).pack(pady=30)

# Call the GUI program
root.mainloop()
