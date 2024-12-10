import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk
import sys
preview_label = None
# Function to decrypt image
def decrypt_image(encrypted_path, key):
    #print("Image Decryption-AES")
    try:
        with open(encrypted_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext
    except Exception as e:
        return None

def main():
    if len(sys.argv)< 2:
        print("Usage: python main.py <image_path>")
        sys.exit(1)

    image_path = sys.argv[1]
    populate_select_image_field(image_path)
    
def populate_select_image_field(image_path):
    entry_encrypted_path.delete(0,tk.END)
    entry_encrypted_path.insert(0,image_path)

# GUI
def select_image():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_encrypted_path.delete(0, tk.END)
        entry_encrypted_path.insert(0, path)

def extract_text_from_image(image):
    pixels = list(image.getdata())
    binary_text = ""

    for pixel in pixels:
        binary_text += str(pixel[0] & 1)

    # Find the index of the start marker '0101001101010100010100110100000101001110010010000101110001101111'
    start_index = binary_text.find('0101001101010100010100110100000101001110010010000101110001101111')

    # Check if the start marker is found and its position is valid
    if start_index != -1 and start_index % 8 == 0:
        binary_text = binary_text[start_index + len('0101001101010100010100110100000101001110010010000101110001101111'):]

        # Convert binary text to ASCII characters
        text = ''.join([chr(int(binary_text[i:i + 8], 2)) for i in range(0, len(binary_text), 8)])

        # Check if there are continuous non-whitespace characters
        if any(c.isalnum() for c in text):
            return text
        else:
            return "No hidden text"

    return "No hidden text"

def decrypt():
    encrypted_path = entry_encrypted_path.get()
    key = entry_decrypt_key.get()

    if len(key) < 16:
        messagebox.showerror("Error", "Please enter at least 16 bytes for the key.")
        return
        
    if "stegano" in encrypted_path.lower():
        messagebox.showinfo("Steganographic Image","The Selected Image is Likely a Steganographic Image.")
        
    decrypted_data = decrypt_image(encrypted_path, key)
    if decrypted_data:
        # Create a folder to store decrypted images
        decrypted_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'aes_decrypt')
        os.makedirs(decrypted_folder, exist_ok=True)
        
        # Save the decrypted image with a new name
        decrypted_image_name = f"aes_decrypt_{os.path.basename(encrypted_path)}"
        decrypted_image_path = os.path.join(decrypted_folder, decrypted_image_name)
        
        with open(decrypted_image_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Decryption Success", f"Decryption successful. Decrypted image saved at aes_decrypt folder.")
        display_decrypted_image_info(decrypted_image_path)
        display_image(decrypted_image_path)
        
        decrypted_image = Image.open(decrypted_image_path)
        hidden_text = extract_text_from_image(decrypted_image)
        if hidden_text:
            messagebox.showinfo("Hidden Text Found",f"The Decrypted Image contains Hidden Text")
            hidden_text_label.config(text=f"\tHidden Text:{hidden_text[:30]}")
    else:
        messagebox.showerror("Error", "Decryption failed. Please check the inputs.")

def display_decrypted_image_info(decrypted_image_path):
    label_decrypted_image.config(text=f"Decrypted Image:\nName: {os.path.basename(decrypted_image_path)}\nPath: {decrypted_image_path}")

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
        
def clear_decryption_input():
    entry_encrypted_path.delete(0, tk.END)
    entry_decrypt_key.delete(0, tk.END)
    label_decrypted_image.config(text="")
    hidden_text_label.config(text="")
    key_length_label_decrypt.config(text="Key Length: 0 bytes")
    # Clear the displayed image for decryption
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        preview_label.destroy()
        preview_label=None
        
def close_app():
    # Close the root window
    root.quit()
    # Show a message box notification
    messagebox.showinfo("Notification", "The application is closed.")
    
root = tk.Tk()
root.title("Image Decryption-AES")
root.geometry("610x450+100+50")

# Decryption fields
label_encrypted_path = tk.Label(root, text="Select Encrypted Image:")
label_encrypted_path.grid(row=0, column=0, sticky="w")

entry_encrypted_path = tk.Entry(root, width=50)
entry_encrypted_path.grid(row=0, column=1, padx=10)

button_browse_encrypted = tk.Button(root, text="Browse", command=select_image)
button_browse_encrypted.grid(row=0, column=2)

label_decrypt_key = tk.Label(root, text="Enter Key:")
label_decrypt_key.grid(row=1, column=0, sticky="w")

entry_decrypt_key = tk.Entry(root, width=50)
entry_decrypt_key.grid(row=1, column=1, padx=10)

key_length_label_decrypt = tk.Label(root, text="Key Length: 0 bytes")
key_length_label_decrypt.grid(row=2, column=1, padx=10)

def on_key_entry_decrypt(event):
    key_length = len(entry_decrypt_key.get())
    key_length_label_decrypt.config(text=f"Key Length: {key_length} bytes.")

entry_decrypt_key.bind('<Key>', on_key_entry_decrypt)
entry_decrypt_key.bind('<KeyRelease>', on_key_entry_decrypt)

button_decrypt = tk.Button(root, text="Decrypt", command=decrypt)
button_decrypt.grid(row=3, column=0, columnspan=3, pady=10)

label_decrypted_image = tk.Label(root, text="")
label_decrypted_image.grid(row=5, column=0, columnspan=3, pady=10)

hidden_text_label= tk.Label(root, text="")
hidden_text_label.grid(row=7, column=0,columnspan=3, pady=10)

# Create the refresh button for decryption
button_refresh_decrypt = tk.Button(root, text="Refresh", command=clear_decryption_input)
button_refresh_decrypt.grid(row=8, column=2, pady=10, padx=5)

button_close_decrypt = tk.Button(root, text="Close App", command=close_app)
button_close_decrypt.grid(row=8, column=0, pady=10, padx=5)

if __name__ == "__main__":
    main()

root.mainloop()