import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk

preview_label = None

# Function to encrypt image with IV
def encrypt_image(image_path, key):
    try:
        image_name = os.path.basename(image_path)
        output_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'encrypted_images')
        os.makedirs(output_folder, exist_ok=True)
        
        # Extract file extension from original image path
        _, image_ext = os.path.splitext(image_name)
        
        # Construct encrypted image path with the same file extension
        output_path = os.path.join(output_folder, 'encrypted_' + os.path.splitext(image_name)[0] + image_ext)
        
        with open(image_path, 'rb') as f:
            plaintext = f.read()
            
        #Generate a random IV
        iv = os.urandom(16)

        cipher = AES.new(key.encode(), AES.MODE_CBC,iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(output_path, 'wb') as f:
            f.write(iv)
            #f.write(cipher.iv) #Write the IV to the file
            f.write(ciphertext)

        return output_path
    except Exception as e:
        return None

# Function to decrypt image with IV
def decrypt_image(encrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f:
            iv = f.read(16) # Read the first 16 bytes to retrieve the IV
            ciphertext = f.read()

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext
    except Exception as e:
        return None

# GUI for encryption
def select_image():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_image.delete(0, tk.END)
        entry_image.insert(0, path)
        display_image_info()
        display_image(path)

def encrypt():
    image_path = entry_image.get()
    key = entry_key.get()

    if len(key) < 16:
        messagebox.showerror("Error", "Please enter at least 16 bytes for the key.")
        return
    elif len(key) == 16:
        rounds = 10
    elif len(key) < 24:
        messagebox.showwarning("Warning", "Consider entering 24 bytes for better security.")
        return
    elif len(key) == 24:
        rounds = 12
    elif len(key) < 32:
        messagebox.showwarning("Warning", "Consider entering 32 bytes for better security.")
        return
    elif len(key) == 32:
        rounds = 14
    else:
        messagebox.showerror("Error", "Please enter at most 32 bytes for the key.")
        return

    encrypted_path = encrypt_image(image_path, key)
    if encrypted_path:
        display_encrypted_image_info(encrypted_path)
        size=len(key)*8
        messagebox.showinfo("Encryption Success", f"Encryption successful with {size} bits,{len(key)} bytes,{rounds} rounds.\n Encrypted Image saved at encrypted_images Folder. ")
        #auto refreshing scheduled
        root.after(10000, auto_refresh)
        root.after(10500, auto_refresh_message)
    else:
        messagebox.showerror("Error", "Encryption failed. Please check the inputs.")

def display_image_info():
    image_path = entry_image.get()
    label_selected_image.config(text=f"Selected Image:\nName: {os.path.basename(image_path)}\nPath: {image_path}")

def display_encrypted_image_info(encrypted_path):
    label_encrypted_image.config(text=f"Encrypted Image:\nName: {os.path.basename(encrypted_path)}\nPath: {encrypted_path}\n\n**Encrypted Image File Format is not Supported to Open!**")

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
        preview_label.grid(row=5, column=0, columnspan=3)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to display preview: {str(e)}")

# Function to decrypt image
def decrypt_image(encrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext
    except Exception as e:
        return None

# GUI for decryption
def select_image_decryption():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_encrypted_path.delete(0, tk.END)
        entry_encrypted_path.insert(0, path)
        display_selected_image_info()

def decrypt():
    encrypted_path = entry_encrypted_path.get()
    key = entry_decrypt_key.get()

    if len(key) < 16:
        messagebox.showerror("Error", "Please enter at least 16 bytes for the key.")
        return

    decrypted_data = decrypt_image(encrypted_path, key)
    if decrypted_data:
        # Create a folder to store decrypted images
        decrypted_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'decrypted_images')
        os.makedirs(decrypted_folder, exist_ok=True)
        
        # Save the decrypted image with a new name
        decrypted_image_name = f"decrypted_{os.path.basename(encrypted_path)}"
        decrypted_image_path = os.path.join(decrypted_folder, decrypted_image_name)
        
        with open(decrypted_image_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo(" Decryption Success", f"Decryption Successful.\nDecrypted Image saved at decrypted_images Folder.")
        display_decrypted_image_info(decrypted_image_path)
        display_image_decryption(decrypted_image_path)
        #auto refreshing scheduled
        root.after(10000, auto_refresh_decrypt)
        root.after(10500, auto_refresh_message_decrypt)
    else:
        messagebox.showerror("Error", "Decryption failed. Please check the inputs.")

def display_selected_image_info():
    image_path = entry_encrypted_path.get()
    label_selected_image_decryption.config(text=f"Selected Image:\nName: {os.path.basename(image_path)}\nPath: {image_path}\n\n**Selected Image is in Encrypted Image File Format,\n is not Supported to Open!**")

def display_decrypted_image_info(decrypted_image_path):
    label_decrypted_image.config(text=f"Decrypted Image:\nName: {os.path.basename(decrypted_image_path)}\nPath: {decrypted_image_path}")

def display_image_decryption(image_path):
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
        preview_label.grid(row=6, column=4, columnspan=3)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to display preview: {str(e)}")

# Function to clear input fields and labels
def clear_input():
    entry_image.delete(0, tk.END)
    entry_key.delete(0, tk.END)
    label_selected_image.config(text="")
    label_encrypted_image.config(text="")
    key_length_label.config(text="Key Length: 0 bytes")
    # Clear the displayed image
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        
    messagebox.showinfo("Refreshed!","Image & Fields are cleared.")

# Function to clear decryption input fields and labels
def clear_decryption_input():
    entry_encrypted_path.delete(0, tk.END)
    entry_decrypt_key.delete(0, tk.END)
    label_selected_image_decryption.config(text="")
    label_decrypted_image.config(text="")
    key_length_label_decrypt.config(text="Key Length: 0 bytes")
    # Clear the displayed image for decryption
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        
    messagebox.showinfo("Refreshed!","Image & Fields are cleared.")

def auto_refresh():
    entry_image.delete(0, tk.END)
    entry_key.delete(0, tk.END)
    label_selected_image.config(text="")
    label_encrypted_image.config(text="")
    key_length_label.config(text="Key Length: 0 bytes")
    # Clear the displayed image
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        
def auto_refresh_decrypt():
    entry_encrypted_path.delete(0, tk.END)
    entry_decrypt_key.delete(0, tk.END)
    label_selected_image_decryption.config(text="")
    label_decrypted_image.config(text="")
    key_length_label_decrypt.config(text="Key Length: 0 bytes")
    # Clear the displayed image for decryption
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        
def auto_refresh_message():
    messagebox.showinfo("Automatically Refreshed", f"Refreshed the Encryption Application.")

def auto_refresh_message_decrypt():
    messagebox.showinfo("Automatically Refreshed", f"Refreshed the Decryption Application.")
    
# Main GUI
root = tk.Tk()
root.title("Image Encryption and Decryption")

# Encryption GUI
print("Image Encryption")
#heading_label = tk.Label(root, text='Image Encryption')
#heading_label.grid(row=0, column=0, columnspan=3, pady=(10,0)) 

label_image = tk.Label(root, text="Select Image:")
label_image.grid(row=0, column=0, sticky="w")

entry_image = tk.Entry(root, width=50)
entry_image.grid(row=0, column=1, padx=10)

button_browse = tk.Button(root, text="Browse", command=select_image)
button_browse.grid(row=0, column=2)

label_key = tk.Label(root, text="Enter Key:")
label_key.grid(row=1, column=0, sticky="w")

entry_key = tk.Entry(root, width=50)
entry_key.grid(row=1, column=1, padx=10)
    
key_length_label = tk.Label(root, text="Key Length: 0 bytes")
key_length_label.grid(row=2, column=1, padx=10)

def on_key_entry(event):
    key_length = len(entry_key.get())
    key_length_label.config(text=f"Key Length: {key_length} bytes.")

entry_key.bind('<Key>', on_key_entry)
entry_key.bind('<KeyRelease>', on_key_entry)

button_encrypt = tk.Button(root, text="Encrypt", command=encrypt)
button_encrypt.grid(row=3, column=0, columnspan=3, pady=10)

label_selected_image = tk.Label(root, text="")
label_selected_image.grid(row=4, column=0, columnspan=3, pady=10)

label_encrypted_image = tk.Label(root, text="")
label_encrypted_image.grid(row=6, column=0, columnspan=3, pady=10)
    
# Add a line between the two applications
separator = ttk.Separator(root, orient='vertical')
separator.grid(row=0, column=3, rowspan=7, sticky='ns', padx=10)

# Decryption GUI
print("Image Decryption")
label_encrypted_path = tk.Label(root, text="Select Encrypted Image:")
label_encrypted_path.grid(row=0, column=4, sticky="w")

entry_encrypted_path = tk.Entry(root, width=50)
entry_encrypted_path.grid(row=0, column=5, padx=10)

button_browse_encrypted = tk.Button(root, text="Browse", command=select_image_decryption)
button_browse_encrypted.grid(row=0, column=6)
    
label_decrypt_key = tk.Label(root, text="Enter Key:")
label_decrypt_key.grid(row=1, column=4, sticky="w")

entry_decrypt_key = tk.Entry(root, width=50)
entry_decrypt_key.grid(row=1, column=5, padx=10)

key_length_label_decrypt = tk.Label(root, text="Key Length: 0 bytes")
key_length_label_decrypt.grid(row=2, column=5, padx=10)

def on_key_entry_decrypt(event):
    key_length = len(entry_decrypt_key.get())
    key_length_label_decrypt.config(text=f"Key Length: {key_length} bytes.")

entry_decrypt_key.bind('<Key>', on_key_entry_decrypt)
entry_decrypt_key.bind('<KeyRelease>', on_key_entry_decrypt)

button_decrypt = tk.Button(root, text="Decrypt", command=decrypt)
button_decrypt.grid(row=3, column=4, columnspan=3, pady=10)

label_selected_image_decryption = tk.Label(root, text="")
label_selected_image_decryption.grid(row=4, column=4, columnspan=3, pady=10)

label_decrypted_image = tk.Label(root, text="")
label_decrypted_image.grid(row=5, column=4, columnspan=3, pady=10)

# Create the refresh button
button_refresh = tk.Button(root, text="Refresh", command=clear_input)
button_refresh.grid(row=3, column=2, pady=10, padx=5)

# Create the refresh button for decryption
button_refresh_decrypt = tk.Button(root, text="Refresh", command=clear_decryption_input)
button_refresh_decrypt.grid(row=3, column=6, pady=10, padx=5)

root.mainloop()