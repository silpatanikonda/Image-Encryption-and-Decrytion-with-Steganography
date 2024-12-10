import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image, ImageTk

# Global variables
public_key = None
private_key = None

# Generate RSA key pair
def generate_key_pair():
    global public_key, private_key
    key = RSA.generate(2048)
    public_key = key.publickey()
    private_key = key

    # Create a folder for RSA key pairs if it doesn't exist
    key_pairs_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_key_pairs')
    os.makedirs(key_pairs_folder, exist_ok=True)

    # Save the key pair
    with open(os.path.join(key_pairs_folder, 'pub_key.pem'), 'wb') as f:
        f.write(public_key.export_key('PEM'))
    with open(os.path.join(key_pairs_folder, 'pvt_key.pem'), 'wb') as f:
        f.write(private_key.export_key('PEM'))

    # Display public key in the text field
    public_key_text.delete('1.0', tk.END)
    public_key_text.insert('1.0', public_key.export_key().decode())
    #private_key_text.delete('1.0', tk.END)
    #private_key_text.insert('1.0', private_key.export_key().decode())

# Encrypt image using RSA
def encrypt_image(image_path):
    try:
        if not public_key:
            messagebox.showerror("Error", "Please generate key pair first.")
            return

        image_name = os.path.basename(image_path)
        output_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_encrypted_images')
        os.makedirs(output_folder, exist_ok=True)
        img_ext = os.path.splitext(image_path)[1]
        output_path = os.path.join(output_folder, 'rsa_encrypted_' + os.path.splitext(image_name)[0] + img_ext)

        with open(image_path, 'rb') as f:
            plaintext = f.read()

        cipher_rsa = PKCS1_OAEP.new(public_key)
        
        # Encrypt the image in blocks
        block_size = public_key.size_in_bytes() - 42  # Subtract padding size
        encrypted_blocks = []
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i+block_size]
            encrypted_block = cipher_rsa.encrypt(block)
            encrypted_blocks.append(encrypted_block)
        
        # Combine encrypted blocks and write to output file
        encrypted_data = b''.join(encrypted_blocks)
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return output_path, image_name, image_path
    except Exception as e:
        print(e)
        return None

# Decrypt image using RSA
def decrypt_image(encrypted_image_path, private_key):
    try:
        if not private_key:
            messagebox.showerror("Error", "Please enter the private key.")
            return

        image_name = os.path.basename(encrypted_image_path)
        output_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_decrypted_images')
        os.makedirs(output_folder, exist_ok=True)
        img_ext = os.path.splitext(image_name)[1]
        output_path = os.path.join(output_folder, 'rsa_decrypted_' + os.path.splitext(image_name)[0] + img_ext)

        with open(encrypted_image_path, 'rb') as f:
            encrypted_data = f.read()

        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # Decrypt the image in blocks
        block_size = private_key.size_in_bytes()
        decrypted_blocks = []
        for i in range(0, len(encrypted_data), block_size):
            block = encrypted_data[i:i+block_size]
            decrypted_block = cipher_rsa.decrypt(block)
            decrypted_blocks.append(decrypted_block)
        
        # Combine decrypted blocks and write to output file
        decrypted_data = b''.join(decrypted_blocks)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return output_path, image_name, encrypted_image_path
    except Exception as e:
        print(e)
        return None

# Select image for encryption
def select_image_for_encryption():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_image_encryption.delete(0, tk.END)
        entry_image_encryption.insert(0, path)
        display_image_preview(path)
        display_image_details("Selected", path, label_selected_image_details)

# Select image for decryption
def select_image_for_decryption():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_image_decryption.delete(0, tk.END)
        entry_image_decryption.insert(0, path)
        display_image_preview(path)
        display_image_details("Selected", path, label_selected_image_details_dec)

# Encrypt image button callback
def encrypt_image_callback():
    image_path = entry_image_encryption.get()
    if not image_path:
        messagebox.showerror("Error", "Please select an image.")
        return
    encrypted_result = encrypt_image(image_path)
    if encrypted_result:
        output_path, image_name, orig_image_path = encrypted_result
        messagebox.showinfo("Encryption Success", f"Encrypted Image saved at {output_path}.")
        display_image_details("Encrypted", output_path, label_encrypted_image_details)
        #display_image_details("Original", orig_image_path, label_original_image_details)
        display_image_preview(output_path)
        #auto refreshing scheduled
        root.after(10000, auto_refresh)
        root.after(10500, auto_refresh_message)
    else:
        messagebox.showerror("Encryption Error", "Failed to encrypt the image.")

# Decrypt image button callback
def decrypt_image_callback():
    image_path = entry_image_decryption.get()
    if not image_path:
        messagebox.showerror("Error", "Please select an image.")
        return
    private_key_str = private_key_text.get("1.0", "end-1c")
    try:
        private_key = RSA.import_key(private_key_str)
    except ValueError as e:
        messagebox.showerror("Error", "Invalid private key format.")
        return
    decrypted_result = decrypt_image(image_path, private_key)
    if decrypted_result:
        output_path, image_name, encrypted_image_path = decrypted_result
        messagebox.showinfo("Decryption Success",f"Decrypted Image saved at {output_path}.")
        display_image_details("Decrypted", output_path, label_decrypted_image_details)
        #display_image_details("Encrypted", encrypted_image_path, label_encrypted_image_details_dec)
        display_image_preview_decryption(output_path)
        #auto refreshing scheduled
        root.after(10000, auto_refresh_decrypt)
        root.after(10500, auto_refresh_message_decrypt)
    else:
        messagebox.showerror("Decryption Error", "Failed to decrypt the image.")

# Display image preview
def display_image_preview(image_path):
    try:
        image = Image.open(image_path)
        image.thumbnail((200, 200))
        photo = ImageTk.PhotoImage(image)
        image_preview_label.configure(image=photo)
        image_preview_label.image = photo
    except Exception as e:
        print(e)

# Display image preview
def display_image_preview_decryption(image_path):
    try:
        image = Image.open(image_path)
        image.thumbnail((200, 200))
        photo = ImageTk.PhotoImage(image)
        decrypted_image_preview_label.configure(image=photo)
        decrypted_image_preview_label.image = photo
    except Exception as e:
        print(e)

# Display image details
def display_image_details(type, image_path, label):
    try:
        image_name = os.path.basename(image_path)
        label.config(text=f"{type} Image Details:\nName: {image_name}\nPath: {image_path}")
    except Exception as e:
        print(e)

# Refresh button callback
def refresh_encryption():
    entry_image_encryption.delete(0, tk.END)
    public_key_text.delete('1.0', tk.END)
    label_selected_image_details.config(text="")
    label_encrypted_image_details.config(text="")
    label_original_image_details.config(text="")
    image_preview_label.config(image="")
    entry_image_encryption.focus()

def auto_refresh():
    entry_image_encryption.delete(0, tk.END)
    public_key_text.delete('1.0', tk.END)
    label_selected_image_details.config(text="")
    label_encrypted_image_details.config(text="")
    label_original_image_details.config(text="")
    image_preview_label.config(image="")
    entry_image_encryption.focus()

def refresh_decryption():
    entry_image_decryption.delete(0, tk.END)
    private_key_text.delete('1.0', tk.END)
    label_selected_image_details_dec.config(text="")
    label_decrypted_image_details.config(text="")
    label_encrypted_image_details_dec.config(text="")
    decrypted_image_preview_label.config(image="")
    entry_image_decryption.focus()

def auto_refresh_decrypt():
    entry_image_decryption.delete(0, tk.END)
    private_key_text.delete('1.0', tk.END)
    label_selected_image_details_dec.config(text="")
    label_decrypted_image_details.config(text="")
    label_encrypted_image_details_dec.config(text="")
    decrypted_image_preview_label.config(image="")
    entry_image_decryption.focus()

def auto_refresh_message():
    messagebox.showinfo("Automatically Refreshed", f"Refreshed the Encryption Application.")

def auto_refresh_message_decrypt():
    messagebox.showinfo("Automatically Refreshed", f"Refreshed the Decryption Application.")

# Main GUI
root = tk.Tk()
root.title("RSA Image Encryption and Decryption")

# Encryption GUI
frame_encryption = tk.LabelFrame(root, text="Image Encryption")
frame_encryption.grid(row=0, column=0, padx=10, pady=10, sticky="w")

label_image_encryption = tk.Label(frame_encryption, text="Select Image:")
label_image_encryption.grid(row=0, column=0, sticky="w")

entry_image_encryption = tk.Entry(frame_encryption, width=50)
entry_image_encryption.grid(row=0, column=1, padx=10)

button_browse_encryption = tk.Button(frame_encryption, text="Browse", command=select_image_for_encryption)
button_browse_encryption.grid(row=0, column=2, padx=10)

button_generate_key_pair = tk.Button(frame_encryption, text="Generate Key Pair", command=generate_key_pair)
button_generate_key_pair.grid(row=1, column=0, columnspan=3, pady=10)

label_public_key = tk.Label(frame_encryption, text="Public Key:")
label_public_key.grid(row=2, column=0, sticky="w")

public_key_text = tk.Text(frame_encryption, height=3, width=50)
public_key_text.grid(row=2, column=1, columnspan=2, padx=10)

label_selected_image_details = tk.Label(frame_encryption, text="")
label_selected_image_details.grid(row=3, column=0, columnspan=3, pady=5)

label_encrypted_image_details = tk.Label(frame_encryption, text="")
label_encrypted_image_details.grid(row=4, column=0, columnspan=3, pady=5)

label_original_image_details = tk.Label(frame_encryption, text="")
label_original_image_details.grid(row=5, column=0, columnspan=3, pady=5)

label_image_preview = tk.Label(frame_encryption, text="Image Preview:")
label_image_preview.grid(row=6, column=0, sticky="w")

image_preview_label = tk.Label(frame_encryption)
image_preview_label.grid(row=6, column=1, columnspan=2, padx=10)

button_refresh_encryption = tk.Button(frame_encryption, text="Refresh", command=refresh_encryption)
button_refresh_encryption.grid(row=7, column=0, columnspan=3, pady=10)

# Decryption GUI
frame_decryption = tk.LabelFrame(root, text="Image Decryption")
frame_decryption.grid(row=2, column=0, padx=10, pady=10, sticky="w")

label_image_decryption = tk.Label(frame_decryption, text="Select Encrypted Image:")
label_image_decryption.grid(row=0, column=0, sticky="w")

entry_image_decryption = tk.Entry(frame_decryption, width=50)
entry_image_decryption.grid(row=0, column=1, padx=10)

button_browse_decryption = tk.Button(frame_decryption, text="Browse", command=select_image_for_decryption)
button_browse_decryption.grid(row=0, column=2, padx=10)

label_private_key = tk.Label(frame_decryption, text="Private Key:")
label_private_key.grid(row=1, column=0, sticky="w")

private_key_text = tk.Text(frame_decryption, height=3, width=50)
private_key_text.grid(row=1, column=1, columnspan=2, padx=10)

label_selected_image_details_dec = tk.Label(frame_decryption, text="")
label_selected_image_details_dec.grid(row=2, column=0, columnspan=3, pady=5)

label_decrypted_image_details = tk.Label(frame_decryption, text="")
label_decrypted_image_details.grid(row=3, column=0, columnspan=3, pady=5)

label_encrypted_image_details_dec = tk.Label(frame_decryption, text="")
label_encrypted_image_details_dec.grid(row=4, column=0, columnspan=3, pady=5)

label_decrypted_image_preview = tk.Label(frame_decryption, text="Decrypted Image Preview:")
label_decrypted_image_preview.grid(row=5, column=0, sticky="w")

decrypted_image_preview_label = tk.Label(frame_decryption)
decrypted_image_preview_label.grid(row=5, column=1, columnspan=2, padx=10)

button_refresh_decryption = tk.Button(frame_decryption, text="Refresh", command=refresh_decryption)
button_refresh_decryption.grid(row=6, column=0, columnspan=3, pady=10)

# Encrypt and Decrypt buttons
button_encrypt = tk.Button(root, text="Encrypt Image", command=encrypt_image_callback)
button_encrypt.grid(row=1, column=0, pady=10)

button_decrypt = tk.Button(root, text="Decrypt Image", command=decrypt_image_callback)
button_decrypt.grid(row=3, column=0, pady=10)

root.mainloop()