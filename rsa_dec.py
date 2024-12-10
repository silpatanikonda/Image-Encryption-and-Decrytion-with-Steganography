import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image, ImageTk
import sys
# Global variables
public_key = None
private_key = None

# Decrypt image using RSA
def decrypt_image(encrypted_image_path, private_key):
    #print("Image Decryption-RSA")
    try:
        if not private_key:
            messagebox.showerror("Error", "Please enter the private key.")
            return
        messagebox.showinfo("Processing","Decryption is in Process....\nPlease Wait")
        image_name = os.path.basename(encrypted_image_path)
        output_folder = os.path.join(os.path.expanduser('~'), 'Desktop', 'rsa_decrypt')
        os.makedirs(output_folder, exist_ok=True)
        img_ext = os.path.splitext(image_name)[1]
        output_path = os.path.join(output_folder, 'rsa_decrypt_' + os.path.splitext(image_name)[0] + img_ext)

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

def main():
    if len(sys.argv)< 2:
        print("Usage: python main.py <image_path>")
        sys.exit(1)

    image_path = sys.argv[1]
    populate_select_image_field(image_path)
    
def populate_select_image_field(image_path):
    entry_image_decryption.delete(0,tk.END)
    entry_image_decryption.insert(0,image_path)

# Select image for decryption
def select_image_for_decryption():
    path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
    if path:
        entry_image_decryption.delete(0, tk.END)
        entry_image_decryption.insert(0, path)
        display_image_details("Selected", path, label_selected_image_details_dec)

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
    if "stegano" in image_path.lower():
        messagebox.showinfo("Steganographic Image","The Selected Image is Likely a Steganographic Image.")
        
    decrypted_result = decrypt_image(image_path, private_key)
    if decrypted_result:
        output_path, image_name, encrypted_image_path = decrypted_result
        messagebox.showinfo("Decryption Success",f"Decryption Successful. Decrypted Image saved at rsa_decrypt folder.")
        display_image_details("Decrypted", output_path, label_decrypted_image_details)
        #display_image_details("Encrypted", encrypted_image_path, label_encrypted_image_details_dec)
        display_image_preview_decryption(output_path)
        
        decrypted_image = Image.open(output_path)
        hidden_text = extract_text_from_image(decrypted_image)
        if hidden_text:
            messagebox.showinfo("Hidden Text Found",f"The Decrypted Image contains Hidden Text")
            hidden_text_label.config(text=f"\tHidden Text:{hidden_text[:30]}")
    else:
        messagebox.showerror("Decryption Error", "Failed to decrypt the image.")

# Display image preview
def display_image_preview_decryption(image_path):
    try:
        image = Image.open(image_path)
        image.thumbnail((200, 150))
        photo = ImageTk.PhotoImage(image)
        decrypted_image_preview_label.configure(image=photo)
        decrypted_image_preview_label.image = photo
    except Exception as e:
        print(e)

# Display image details
def display_image_details(type, image_path, label):
    try:
        image_name = os.path.basename(image_path)
        label.config(text=f"{type} Image Details:\nName: {image_name}\nPath: {image_path}\n\nDecrypted Image Preview:")
    except Exception as e:
        print(e)

def refresh_decryption():
    entry_image_decryption.delete(0, tk.END)
    private_key_text.delete('1.0', tk.END)
    label_decrypted_image_details.config(text="")
    decrypted_image_preview_label.config(image="")
    hidden_text_label.config(text="")
    entry_image_decryption.focus()
    
def close_app():
    # Close the root window
    root.quit()
    # Show a message box notification
    messagebox.showinfo("Notification", "The application is closed.")

# Main GUI
root = tk.Tk()
root.title("Image Decryption-RSA")

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

label_decrypted_image_details = tk.Label(frame_decryption, text="")
label_decrypted_image_details.grid(row=4, column=0, columnspan=3, pady=5)

decrypted_image_preview_label = tk.Label(frame_decryption)
decrypted_image_preview_label.grid(row=6,column=1, padx=10, pady=10, sticky="nsew")

frame_decryption.grid_rowconfigure(6, weight=1)
frame_decryption.grid_columnconfigure(1, weight=1)

button_refresh_decryption = tk.Button(frame_decryption, text="Refresh", command=refresh_decryption)
button_refresh_decryption.grid(row=9, column=3, pady=10)

button_decrypt = tk.Button(frame_decryption, text="Decrypt Image", command=decrypt_image_callback)
button_decrypt.grid(row=3, column=1, pady=10)

hidden_text_label = tk.Label(frame_decryption)
hidden_text_label.grid(row=7,column=1,padx=10,pady=10)

button_close = tk.Button(frame_decryption, text="Close App", command=close_app)
button_close.grid(row=9, column=0, pady=10)

if __name__ == "__main__":
    main()
root.mainloop()