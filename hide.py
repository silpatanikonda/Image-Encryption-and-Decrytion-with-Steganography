import tkinter as tk
from tkinter import ttk, filedialog, messagebox, StringVar
from PIL import Image, ImageTk
import os

class SteganographyApp:
    def __init__(self, parent):
        self.parent = parent
        self.page = ttk.Frame(parent)
        parent.add(self.page, text="Hiding Text App")

        # Variables
        self.image_path = StringVar()
        self.text_to_hide = StringVar()

        # UI Elements
        tk.Label(self.page, text="Image Steganography", font=("Helvetica", 16, "bold")).grid(row=0, columnspan=2, pady=10)

        tk.Label(self.page, text="Select Image:").grid(row=1, column=0, pady=5)
        self.image_entry = tk.Entry(self.page, textvariable=self.image_path, state="readonly", width=30)
        self.image_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.page, text="Browse", command=self.browse_image).grid(row=1, column=2, pady=5)

        tk.Label(self.page, text="Enter Text to Hide:").grid(row=2, column=0, pady=5)
        self.text_entry = tk.Entry(self.page, textvariable=self.text_to_hide, width=30)
        self.text_entry.grid(row=2, column=1, pady=5)
        tk.Button(self.page, text="Hide Text", command=self.hide_text).grid(row=2, column=2, pady=5)

        # Display Selected Image Details
        tk.Label(self.page, text="Selected Image Details:").grid(row=3, column=1, pady=5)
        self.image_details_label = tk.Label(self.page, text="")
        self.image_details_label.grid(row=4, column=0, pady=10, columnspan=3)

        # Display Output Image Details
        tk.Label(self.page, text="Output Image Details:").grid(row=7, column=1, pady=5)
        self.image_details_label2 = tk.Label(self.page, text="")
        self.image_details_label2.grid(row=8, column=0, pady=10, columnspan=3)
        
        self.refresh_button = tk.Button(self.page, text="Refresh", command=self.refresh_fields)
        self.refresh_button.grid(row=9, column=0, pady=5)

        # Image Preview Area
        tk.Label(self.page, text="Image Preview:").grid(row=5, column=1)
        self.image_preview_label = tk.Label(self.page)
        self.image_preview_label.grid(row=6, column=1, pady=5)

        # Close Button
        self.close_button = tk.Button(self.page, text="Close App", command=self.close_window)
        self.close_button.grid(row=9, column=2, pady=10)

    def browse_image(self):
        file_path = filedialog.askopenfilename(title="Select Image File", filetypes=[("Image files", "*")])
        if file_path:
            self.image_path.set(file_path)
            self.display_image_details(file_path)
            self.display_image_preview(file_path)

    def display_image_details(self, file_path):
        file_name = os.path.basename(file_path)
        self.image_details_label.config(text=f"\tName: {file_name}\n\tPath: {file_path}")
        
    def display_image_details2(self, stegano_image_path):
        file_name2 = os.path.basename(stegano_image_path)
        self.image_details_label2.config(text=f"\tName: {file_name2}\n\tPath:{stegano_image_path}")

    def hide_text(self):
        image_path = self.image_path.get()
        text_to_hide1 = self.text_to_hide.get()
        text_to_hide2 = text_to_hide1 + '                                                                     '
        
        if text_to_hide2 == '                                                                     ':
            text_to_hide = ""
        else:
            text_to_hide = text_to_hide2

        # Check if image_path and text_to_hide are not empty
        if not image_path or not text_to_hide:
            messagebox.showerror("Error", "Please select an image and enter text to hide.")
            return
            
        messagebox.showinfo("Processing","Steganography is in Process....\nPlease Wait")

        try:
            # Read the image
            image = Image.open(image_path)

            # Convert the text to binary
            text_binary = ''.join(format(ord(char), '08b') for char in text_to_hide)

            # Add a delimiter to indicate the start of steganographic information
            delimiter = '0101001101010100010100110100000101001110010010000101110001101111'
            text_binary = delimiter + text_binary

            # Flatten the image pixels
            pixels = list(image.getdata())
            pixels = [list(pixel) for pixel in pixels]

            # Embed text into the image using LSB (modify only the first channel)
            pixel_index = 0
            for i in range(len(text_binary)):
                pixel = pixels[pixel_index]
                pixel[0] = (pixel[0] & 0xFE) | int(text_binary[i])
                pixel_index += 1

            # Create a new image with the modified pixels
            new_image = Image.new("RGB", image.size)
            new_pixels = [tuple(pixel) for pixel in pixels]
            new_image.putdata(new_pixels)

            # Save the steganographic image
            stegano_folder_path = os.path.join(os.path.expanduser("~"), "Desktop", "stegano-images")
            os.makedirs(stegano_folder_path, exist_ok=True)

            # Save the steganographic image with a new name
            stegano_image_name = f"stegano_{os.path.basename(image_path)}"
            stegano_image_path = os.path.join(stegano_folder_path, stegano_image_name)
            new_image.save(stegano_image_path, format="PNG")

            self.display_image_details2(stegano_image_path)
            messagebox.showinfo("Image Steganography Success", f"Successfully Text is Hidden in Image.\nSteganographic Image is stored at stegano-images folder.")

        except FileNotFoundError as e:
            messagebox.showerror("Error", f"File not found: {image_path}\nError: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def display_image_preview(self, file_path):
        # Resize image to fit preview area
        image = Image.open(file_path)
        image.thumbnail((220, 220))
        img = ImageTk.PhotoImage(image)
        self.image_preview_label.config(image=img)
        self.image_preview_label.image = img

    def refresh_fields(self):
        self.image_path.set("")
        self.text_to_hide.set("")
        self.image_details_label.config(text="")
        self.image_details_label2.config(text="")
        self.image_preview_label.config(image="")

    def close_window(self):
        self.parent.quit()

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography App")

        # Set the window size (width x height + x_offset + y_offset)
        self.root.geometry("500x650+100+50")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")

        self.steganography_app = SteganographyApp(self.notebook)
        
    def check_current_tab(self, event):
        current_tab = self.notebook.tk.call(self.notebook._w, "identify", "tab", event.x, event.y)
        if current_tab == "1":
            self.steganography_app.text_to_hide.set("")
            self.steganography_app.image_path.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()