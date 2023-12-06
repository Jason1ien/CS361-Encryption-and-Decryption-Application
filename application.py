import tkinter as tk
from tkinter import ttk
import tkinter.simpledialog
import pyperclip
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

INPUT_SERVICE = 'inputService.txt'
OUTPUT_SERVICE = 'outputService.txt'
encryption_key = "" # This variable will store the encryption key
decryption_key = "" # This variable will store the decryption key
iv = os.urandom(16) # Create a random 128-bit initialization vector.

def generate_random_plaintext():
    """ This function generates a random plaintext by writing 'run' to a file
    and then reading the content of the file. 

    Args:
        None

    Returns:
        None
    """
    f = open(INPUT_SERVICE, 'w', encoding="utf-8")
    f.write('run');
    f.close()
    time.sleep(0.1)
    f = open(OUTPUT_SERVICE, 'r', encoding="utf-8")
    plaintext = f.read();
    f.close()
    
    input_text_encrypt.delete(1.0, tk.END)
    input_text_encrypt.insert(tk.END, plaintext)
    pass

def copy_to_clipboard(text_to_copy):
    """Copy the given text to the clipboard.

    Args:
        text_to_copy (str): The text to be copied to the clipboard.

    Returns:
        None
    """
    pyperclip.copy(text_to_copy)
    pass

    if encryption_key != decryption_key:
        
        # Set up warning message box
        warning = "WARNING: Keys do not match. Decryption might fail.\n\nDo you want to continue?"
        result = tkinter.messagebox.askyesno("Warning", warning)
        if result:
            print('Decryption continued')
        else:
            print('Decryption stopped')
    pass

def clear_all():
    """Clear the contents of all input boxes.

    Args:
        None

    Returns:
        None
    """
    input_text_encrypt.delete(1.0, tk.END)
    key_entry_encrypt.delete(0, tk.END)
    output_text_encrypt.delete(1.0, tk.END)
    input_text_decrypt.delete(1.0, tk.END)
    key_entry_decrypt.delete(0, tk.END)
    output_text_decrypt.delete(1.0, tk.END)

def open_help_window():
    """Open a new window for help information.

    Args:
        None

    Returns:
        None
    """
    help_window = tk.Toplevel(root)
    help_window.title("Help Information")
    
    help_text = """
                                                *** | User Manual | ***
    
    1. **Encryption Tab:**
        - Input Box:** Enter the plaintext you want to encrypt.
        - Key Box:** Enter the encryption key.
        - Encrypt Button:** Press to encrypt the plaintext.
        - Output Box:** Displays the encrypted ciphertext.
        
    2. **Decryption Tab:**
        - Input Box:** Enter the ciphertext you want to decrypt.
        - Key Box:** Enter the decryption key.
        - Decrypt Button:** Press to decrypt the ciphertext.
        - Output Box:** Displays the decrypted plaintext.
        
    3. **Buttons:**
        - Generate Random Plaintext:** Generates a random plaintext for encryption.
        - Copy to Clipboard:** Copies the selected text to the clipboard.
        - Help Button:** Opens this help window.
        - Clear All Button:** Clears all input and output boxes.

    **Encryption Scheme: AES-CBC Mode**
    
    The program uses the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC) mode for encryption. 
    AES is a widely used symmetric encryption algorithm, and CBC is a block cipher mode that provides confidentiality 
    by XORing each block of plaintext with the previous ciphertext block before encryption. This adds an extra layer 
    of security and helps prevent patterns in the plaintext from being visible in the ciphertext.

    Update Log:
    - v1.0 (Initial Release): Basic encryption and decryption functionality.
    - v1.1: Added random plaintext generation and help window.
    - v1.2: Improved user interface and added clear all button.
    """
    
    help_label = ttk.Label(help_window, text=help_text)
    help_label.pack(padx=10, pady=10)

def encrypt(key, plaintext, iv):
    """Encrypt the plaintext using AES-CBC mode.

    Args:
        key (bytes): The encryption key.
        plaintext (bytes): The plaintext to be encrypted.
        iv (bytes): The initialization vector.

    Returns:
        tuple: A tuple containing the initialization vector and the ciphertext.
    """
    # Create a Cipher object with AES-CBC mode.
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()

    # Pad the plaintext to be a multiple of the block size (16 bytes).
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext.
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return (iv, ciphertext)

def decrypt(key, iv, ciphertext):
    """Decrypt the ciphertext using AES-CBC mode.

    Args:
        key (bytes): The decryption key.
        iv (bytes): The initialization vector.
        ciphertext (bytes): The ciphertext to be decrypted.

    Returns:
        bytes: The decrypted plaintext.
    """
    # Create a Cipher object with AES-CBC mode.
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()

    # Decrypt the ciphertext.
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext.
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def encrypt_button():
    """Encrypt the plaintext and display the ciphertext.

    Args:
        None

    Returns:
        None
    """
    
    global encryption_key
    # Retrieve all textbox values
    encryption_key = key_entry_encrypt.get()
    padded_encryption_key = encryption_key.ljust(16, " ").encode("utf-8")
    plaintext = input_text_encrypt.get(1.0, tk.END)
    plaintext = str.encode(plaintext)
    
    global iv
    
    # Encrypt the plaintext.
    iv, ciphertext = encrypt(padded_encryption_key, plaintext, iv)
    ciphertext_decoded = ciphertext.hex()
    
    # Update the textbox
    output_text_encrypt.delete(1.0, tk.END)
    output_text_encrypt.insert(tk.END, ciphertext_decoded)

    pass

def decrypt_button():
    """Decrypt the ciphertext and display the plaintext.

    Args:
        None

    Returns:
        None
    """
    
    global decryption_key
    decryption_key = key_entry_decrypt.get()

    # Check if keys match
    if encryption_key != decryption_key:
        #tkinter.messagebox.showwarning("Warning", "KEYS DO NOT MATCH\n\nDECRYPTION MIGHT FAIL")

        warning = "WARNING: Keys do not match. Decryption might fail.\n\nDo you want to continue?"
        result = tkinter.messagebox.askyesno("Warning", warning)
        if result:
            #continue with decryption
            print('Decryption continued')
        else:
            #stop decryption
            print('Decryption stopped')
            return 0
    
    # Check if ciphertexts match
    decryption_key = key_entry_decrypt.get()
    decryption_key = decryption_key.ljust(16, " ").encode("utf-8")
    ciphertext = input_text_decrypt.get(1.0, tk.END)
    ciphertext = bytes.fromhex(ciphertext)
    
    global iv
    
    # Decrypt the ciphertext.
    plaintext = decrypt(decryption_key, iv, ciphertext)
    
    # Update the textbox
    output_text_decrypt.delete(1.0, tk.END)
    output_text_decrypt.insert(tk.END, plaintext)
    
    pass








###################################### USER INTERFACE ######################################

# Main window
root = tk.Tk()
root.title("Text Encryption and Decryption")

# Encryption Frame on the left
encryption_frame = ttk.LabelFrame(root, text="Encryption")
encryption_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Input textbox for encryption
input_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Input")
input_frame_encrypt.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

# Generate Random Plaintext button and textbox
generate_plaintext_button = ttk.Button(input_frame_encrypt, text="Generate Random Plaintext", command=generate_random_plaintext)
generate_plaintext_button.grid(row=0, column=0, padx=10, pady=10)

input_text_encrypt = tk.Text(input_frame_encrypt, width=40, height=6)
input_text_encrypt.grid(row=1, column=0, padx=10, pady=10)

# Key frame for encryption
key_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Key")
key_frame_encrypt.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
key_entry_encrypt = ttk.Entry(key_frame_encrypt)
key_entry_encrypt.grid(row=0, column=0, padx=10, pady=10)
copy_key_button_encrypt = ttk.Button(key_frame_encrypt, text="Copy to Clipboard", command=lambda: copy_to_clipboard(key_entry_encrypt.get()))
copy_key_button_encrypt.grid(row=0, column=1, padx=10, pady=10)

# Encryption button
generate_button_encrypt = ttk.Button(encryption_frame, text="Encrypt", command=encrypt_button)
generate_button_encrypt.grid(row=3, column=0, padx=10, pady=10)

# Output textbox encryption
output_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Output (Requires a Key and Input)")
output_frame_encrypt.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
output_text_encrypt = tk.Text(output_frame_encrypt, width=40, height=6)
output_text_encrypt.grid(row=0, column=0, padx=10, pady=10)

# Decryption Frame
decryption_frame = ttk.LabelFrame(root, text="Decryption")
decryption_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

# Input text for Decryption
input_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Ciphertext")
input_frame_decrypt.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
input_text_decrypt = tk.Text(input_frame_decrypt, width=40, height=6)
input_text_decrypt.grid(row=0, column=0, padx=10, pady=10)

# Key frame for decrpytion
key_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Key")
key_frame_decrypt.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
key_entry_decrypt = ttk.Entry(key_frame_decrypt)
key_entry_decrypt.grid(row=0, column=0, padx=10, pady=10)
copy_key_button_decrypt = ttk.Button(key_frame_decrypt, text="Copy to Clipboard", command=lambda: copy_to_clipboard(key_entry_decrypt.get()))
copy_key_button_decrypt.grid(row=0, column=1, padx=10, pady=10)

# Decrypt button for decryption
decipher_button_decrypt = ttk.Button(decryption_frame, text="Decrypt", command=decrypt_button)
decipher_button_decrypt.grid(row=3, column=0, padx=10, pady=10)

warning_label = ttk.Label(key_frame_decrypt, text="", foreground="red")
warning_label.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

# Output textbox for decryption
output_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Output (Requires a Key and Ciphertext)")
output_frame_decrypt.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
output_text_decrypt = tk.Text(output_frame_decrypt, width=40, height=6)
output_text_decrypt.grid(row=0, column=0, padx=10, pady=10) 

# Help button
help_button = ttk.Button(root, text="Help", command=open_help_window)
help_button.grid(row=1, column=0, padx=10, pady=10, sticky="w")

# Clear all button
clear_all_button = ttk.Button(root, text="Clear All", command=clear_all)
clear_all_button.grid(row=1, column=1, padx=10, pady=10, sticky="e")

# Use grid weights to make the frames expand with the window
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

root.mainloop()