import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk
import sys
preview_label = None

# Function to decrypt image with IV in CBC mode
def decrypt_image(encrypted_path, key1, key2):
    #print("Image Decryption-3DES")
    try:
        with open(encrypted_path, 'rb') as f:
            iv = f.read(8)  # Read the first 8 bytes to retrieve the IV
            ciphertext = f.read()

        # Triple DES decryption
        cipher = DES3.new(key1.encode(), DES3.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        
        cipher = DES3.new(key2.encode(), DES3.MODE_CBC, iv)
        plaintext = cipher.encrypt(plaintext)
        
        cipher = DES3.new(key1.encode(), DES3.MODE_CBC, iv)
        plaintext = cipher.decrypt(plaintext)

        return plaintext
    except Exception as e:
        print(e)
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

# Function to select encrypted image for decryption
def select_encrypted_image():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_encrypted_path.delete(0, tk.END)
        entry_encrypted_path.insert(0, path)
        display_selected_image_info()

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
    key1 = entry_decrypt_key1.get()
    key2 = entry_decrypt_key2.get()

    if not key1 or not key2:
        messagebox.showerror("Error", "Please enter keys.")
        return

    if len(key1) not in [16, 24] or len(key2) not in [16, 24]:
        messagebox.showerror("Error", "Please enter either 16 or 24 bytes for each key.")
        return
        
    if not encrypted_path:
        messagebox.showerror("Error", "Please select encrypted image.")
        return
        
    if "stegano" in encrypted_path.lower():
        messagebox.showinfo("Steganographic Image","The Selected Image is Likely a Steganographic Image.")

    decrypted_data = decrypt_image(encrypted_path, key1, key2)
    if decrypted_data:
        # Create a folder to store decrypted images
        decrypted_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'des_decrypt')
        os.makedirs(decrypted_folder, exist_ok=True)
        
        # Save the decrypted image with a new name
        decrypted_image_name = f"des_decrypt_{os.path.basename(encrypted_path)}"
        decrypted_image_path = os.path.join(decrypted_folder, decrypted_image_name)
        
        with open(decrypted_image_path, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Decryption Success", f"Decryption Successful. Decrypted Image saved at des_decrypted_images folder.")
        display_decrypted_image_info(decrypted_image_path)
        decrypted_image = Image.open(decrypted_image_path)
        hidden_text = extract_text_from_image(decrypted_image)
        if hidden_text:
            messagebox.showinfo("Hidden Text Found",f"The Decrypted Image contains Hidden Text")
            hidden_text_label.config(text=f"\tHidden Text:{hidden_text[:30]}")
    else:
        messagebox.showerror("Error", "Decryption failed. Please check the inputs.")

def display_decrypted_image_info(decrypted_image_path):
    label_decrypted_image.config(text=f"Decrypted Image:\nName: {os.path.basename(decrypted_image_path)}\nPath: {decrypted_image_path}")
    display_image_decryption(decrypted_image_path)

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
        preview_label.grid(row=8, column=4, columnspan=3)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to display preview: {str(e)}")

# Function to clear decryption input fields and labels
def clear_decryption_input():
    entry_encrypted_path.delete(0, tk.END)
    entry_decrypt_key1.delete(0, tk.END)
    entry_decrypt_key2.delete(0, tk.END)
    label_decrypted_image.config(text="")
    key_length_label_decrypt1.config(text="Key Length: 0 bytes")
    key_length_label_decrypt2.config(text="Key Length: 0 bytes")
    hidden_text_label.config(text="")
    # Clear the displayed image for decryption
    global preview_label
    if preview_label:
        preview_label.grid_forget()
        
def close_app():
    # Close the root window
    root.quit()
    # Show a message box notification
    messagebox.showinfo("Notification", "The application is closed.")

# Main GUI
root = tk.Tk()
root.title("Image Decryption-3DES")

# Decryption GUI
label_encrypted_path = tk.Label(root, text="Select Encrypted Image:")
label_encrypted_path.grid(row=0, column=4, sticky="w")

entry_encrypted_path = tk.Entry(root, width=50)
entry_encrypted_path.grid(row=0, column=5, padx=10)

button_browse_encrypted = tk.Button(root, text="Browse", command=select_encrypted_image)
button_browse_encrypted.grid(row=0, column=6)
    
label_decrypt_key1 = tk.Label(root, text="Enter Key 1:")
label_decrypt_key1.grid(row=1, column=4, sticky="w")

entry_decrypt_key1 = tk.Entry(root, width=50)
entry_decrypt_key1.grid(row=1, column=5, padx=10)

key_length_label_decrypt1 = tk.Label(root, text="Key Length: 0 bytes")
key_length_label_decrypt1.grid(row=2, column=5, padx=10)

def on_key_entry_decrypt1(event):
    key_length = len(entry_decrypt_key1.get())
    key_length_label_decrypt1.config(text=f"Key Length: {key_length} bytes.")

entry_decrypt_key1.bind('<Key>', on_key_entry_decrypt1)
entry_decrypt_key1.bind('<KeyRelease>', on_key_entry_decrypt1)

label_decrypt_key2 = tk.Label(root, text="Enter Key 2:")
label_decrypt_key2.grid(row=3, column=4, sticky="w")

entry_decrypt_key2 = tk.Entry(root, width=50)
entry_decrypt_key2.grid(row=3, column=5, padx=10)

key_length_label_decrypt2 = tk.Label(root, text="Key Length: 0 bytes")
key_length_label_decrypt2.grid(row=4, column=5, padx=10)

def on_key_entry_decrypt2(event):
    key_length = len(entry_decrypt_key2.get())
    key_length_label_decrypt2.config(text=f"Key Length: {key_length} bytes.")

entry_decrypt_key2.bind('<Key>', on_key_entry_decrypt2)
entry_decrypt_key2.bind('<KeyRelease>', on_key_entry_decrypt2)

button_decrypt = tk.Button(root, text="Decrypt", command=decrypt)
button_decrypt.grid(row=5, column=4, columnspan=3, pady=10)

label_decrypted_image = tk.Label(root, text="")
label_decrypted_image.grid(row=7, column=4, columnspan=3, pady=10)

hidden_text_label= tk.Label(root, text="")
hidden_text_label.grid(row=9, column=4,columnspan=3, pady=10)

button_close = tk.Button(root, text="Close App", command=close_app)
button_close.grid(row=10, column=4, columnspan=3, pady=10)

# Create the refresh button for decryption
button_refresh_decrypt = tk.Button(root, text="Refresh", command=clear_decryption_input)
button_refresh_decrypt.grid(row=5, column=6, pady=10, padx=5)

if __name__ == "__main__":
    main()

root.mainloop()