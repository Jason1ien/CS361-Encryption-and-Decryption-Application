import tkinter as tk
from tkinter import ttk
import tkinter.simpledialog
import pyperclip

encryption_key = "" # This variable will store the encryption key
decryption_key = "" # This variable will store the decryption key

def generate_random_plaintext():
    # This function generates a random plaintext and populates the input text box.
    pass

def generate_cipher():
    # This function will be called when the "Generate Cipher" button is pressed.
    global encryption_key
    encryption_key = key_entry_encrypt.get()
    # Add encryption logic here.
    pass

def copy_to_clipboard(text_to_copy):
    # This function copies the given text to the clipboard.
    pyperclip.copy(text_to_copy)

def decipher_text():
    # This function will be called when the "Decipher" button is pressed.
    global decryption_key
    decryption_key = key_entry_decrypt.get()

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
    pass

# Create the main window
root = tk.Tk()
root.title("Text Encryption and Decryption")

# Create the encryption frame on the left
encryption_frame = ttk.LabelFrame(root, text="Encryption")
encryption_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Create and configure the input frame for encryption
input_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Input")
input_frame_encrypt.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

# Create the "Generate Random Plaintext" button
generate_plaintext_button = ttk.Button(input_frame_encrypt, text="Generate Random Plaintext", command=generate_random_plaintext)
generate_plaintext_button.grid(row=0, column=0, padx=10, pady=10)

input_text_encrypt = tk.Text(input_frame_encrypt, width=40, height=6)
input_text_encrypt.grid(row=1, column=0, padx=10, pady=10)

# Create and configure the key frame for encryption
key_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Key")
key_frame_encrypt.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
key_entry_encrypt = ttk.Entry(key_frame_encrypt)
key_entry_encrypt.grid(row=0, column=0, padx=10, pady=10)
copy_key_button_encrypt = ttk.Button(key_frame_encrypt, text="Copy to Clipboard", command=lambda: copy_to_clipboard(key_entry_encrypt.get()))
copy_key_button_encrypt.grid(row=0, column=1, padx=10, pady=10)

# Create the "Generate Cipher" button for encryption
generate_button_encrypt = ttk.Button(encryption_frame, text="Generate Cipher", command=generate_cipher)
generate_button_encrypt.grid(row=3, column=0, padx=10, pady=10)

# Create and configure the output frame for encryption
output_frame_encrypt = ttk.LabelFrame(encryption_frame, text="Output")
output_frame_encrypt.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
output_text_encrypt = tk.Text(output_frame_encrypt, width=40, height=6)
output_text_encrypt.grid(row=0, column=0, padx=10, pady=10)

# Create the decryption frame on the right
decryption_frame = ttk.LabelFrame(root, text="Decryption")
decryption_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

# Create and configure the input frame for decryption
input_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Ciphertext")
input_frame_decrypt.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
input_text_decrypt = tk.Text(input_frame_decrypt, width=40, height=6)
input_text_decrypt.grid(row=0, column=0, padx=10, pady=10)

# Create and configure the key frame for decryption
key_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Key")
key_frame_decrypt.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
key_entry_decrypt = ttk.Entry(key_frame_decrypt)
key_entry_decrypt.grid(row=0, column=0, padx=10, pady=10)
copy_key_button_decrypt = ttk.Button(key_frame_decrypt, text="Copy to Clipboard", command=lambda: copy_to_clipboard(key_entry_decrypt.get()))
copy_key_button_decrypt.grid(row=0, column=1, padx=10, pady=10)

# Create the "Decipher" button for decryption
decipher_button_decrypt = ttk.Button(key_frame_decrypt, text="Decipher", command=decipher_text)
decipher_button_decrypt.grid(row=0, column=2, padx=10, pady=10)

warning_label = ttk.Label(key_frame_decrypt, text="", foreground="red")
warning_label.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Create and configure the output frame for decryption
output_frame_decrypt = ttk.LabelFrame(decryption_frame, text="Output")
output_frame_decrypt.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
output_text_decrypt = tk.Text(output_frame_decrypt, width=40, height=6)
output_text_decrypt.grid(row=0, column=0, padx=10, pady=10)

# Use grid weights to make the frames expand with the window
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

root.mainloop()