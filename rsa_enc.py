import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image, ImageTk

preview_label = None
public_key = None
private_key = None

# Function to generate RSA key pair
def generate_key_pair():
    global public_key, private_key
    key = RSA.generate(2048)
    public_key = key.publickey()
    private_key = key
    
    image_path = entry_image.get()
    image_name = os.path.basename(image_path)

    # Create a folder for RSA key pairs if it doesn't exist
    key_pairs_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_key_pairs')
    os.makedirs(key_pairs_folder, exist_ok=True)

    # Save the public key
    pub_key_filename = f'pub_key_{image_name}.pem'
    with open(os.path.join(key_pairs_folder, pub_key_filename), 'wb') as f:
        f.write(public_key.export_key('PEM'))

    # Save the private key
    pri_key_filename = f'pvt_key_{image_name}.pem'
    with open(os.path.join(key_pairs_folder, pri_key_filename), 'wb') as f:
        f.write(private_key.export_key('PEM'))

    # Display public key in the text field
    public_key_text.delete('1.0', tk.END)
    public_key_text.insert('1.0', public_key.export_key().decode())

# Function to encrypt image with RSA
def encrypt_image(image_path):
    #print("Image Encryption-RSA")
    try:
        if not public_key:
            messagebox.showerror("Error", "Please generate key pair first.")
            return
            
        messagebox.showinfo("Processing","Encryption is in Process....\nPlease Wait")

        image_name = os.path.basename(image_path)
        output_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_encrypt')
        os.makedirs(output_folder, exist_ok=True)
        img_ext = os.path.splitext(image_path)[1]
        output_path = os.path.join(output_folder, 'rsa_encrypt_' + os.path.splitext(image_name)[0] + img_ext)

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

        return output_path
    except Exception as e:
        print(e)
        return None

# Function to display public key in text field
def display_public_key():
    if public_key:
        public_key_text.delete('1.0', tk.END)
        public_key_text.insert('1.0', public_key.export_key().decode())

# Function to clear the text field
def clear_public_key():
    public_key_text.delete('1.0', tk.END)

# Function to select image
def select_image():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_image.delete(0, tk.END)
        entry_image.insert(0, path)
        display_image_info()
        display_image(path)

# Function to encrypt image
def encrypt():
    image_path = entry_image.get()
    
    if not image_path:
        messagebox.showerror("Error", "Please select an image.")
        return

    encrypted_path = encrypt_image(image_path)
    if encrypted_path:
        display_encrypted_image_info(encrypted_path)
        messagebox.showinfo("Encryption Success", "Encryption successful. Encrypted Image saved at rsa_encrypted_images folder.")
    else:
        messagebox.showerror("Error", "Encryption failed. Please check the inputs.")

# Function to display image information
def display_image_info():
    image_path = entry_image.get()
    label_selected_image.config(text=f"Selected Image:\nName: {os.path.basename(image_path)}\nPath: {image_path}")

# Function to display encrypted image information
def display_encrypted_image_info(encrypted_path):
    label_encrypted_image.config(text=f"Encrypted Image:\nName: {os.path.basename(encrypted_path)}\nPath: {encrypted_path}\n\n*Encrypted Image File Format is not Supported to Open!*")

# Function to display image
def display_image(image_path):
    global preview_label
    try:
        if not os.path.exists(image_path):
            raise FileNotFoundError("Selected image does not exist")

        # Open and resize the image
        preview_image = Image.open(image_path)
        preview_image = preview_image.resize((200, 150), Image.LANCZOS)

        # Convert the image to PhotoImage format
        preview_image = ImageTk.PhotoImage(preview_image)

        # Create a label to display the image
        preview_label = tk.Label(root, image=preview_image)
        preview_label.image = preview_image
        preview_label.grid(row=6, column=0, columnspan=3)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to display preview: {str(e)}")

# Refresh button callback
def refresh_encryption():
    entry_image.delete(0, tk.END)
    public_key_text.delete('1.0', tk.END)
    label_selected_image.config(text="")
    label_encrypted_image.config(text="")
    #label_original_image_details.config(text="")
    if preview_label:
        preview_label.config(image="")
    entry_image.focus()

def close_app():
    # Close the root window
    root.quit()
    # Show a message box notification
    messagebox.showinfo("Notification", "The application is closed.")

# Main GUI
root = tk.Tk()
root.title("Image Encryption-RSA")

# Encryption GUI
label_image = tk.Label(root, text="Select Image:")
label_image.grid(row=0, column=0, sticky="w")

entry_image = tk.Entry(root, width=50)
entry_image.grid(row=0, column=1, padx=10)

button_browse = tk.Button(root, text="Browse", command=select_image)
button_browse.grid(row=0, column=2)

button_generate_key_pair = tk.Button(root, text="Generate Key Pair", command=generate_key_pair)
button_generate_key_pair.grid(row=1, column=0, columnspan=3, pady=10)

label_public_key = tk.Label(root, text="Public Key:")
label_public_key.grid(row=2, column=0, sticky="w")

public_key_text = tk.Text(root, height=3, width=50)
public_key_text.grid(row=2, column=1, columnspan=2, padx=10)

button_display_public_key = tk.Button(root, text="Display Key", command=display_public_key)
button_display_public_key.grid(row=3, column=1, pady=5)

button_clear_public_key = tk.Button(root, text="Hide", command=clear_public_key)
button_clear_public_key.grid(row=3, column=2, pady=5)

button_encrypt = tk.Button(root, text="Encrypt", command=encrypt)
button_encrypt.grid(row=4, column=0, columnspan=3, pady=10)

button_refresh_encryption = tk.Button(root, text="Refresh", command=refresh_encryption)
button_refresh_encryption.grid(row=4, column=2, columnspan=3, pady=10)

label_selected_image = tk.Label(root, text="")
label_selected_image.grid(row=5, column=0, columnspan=3, pady=10)

label_encrypted_image = tk.Label(root, text="")
label_encrypted_image.grid(row=7, column=0, columnspan=3, pady=10)

button_close = tk.Button(root, text="Close App", command=close_app)
button_close.grid(row=8,column=1,pady=10)

root.mainloop()