import tkinter as tk
from tkinter import ttk, filedialog, messagebox, StringVar
from PIL import Image, ImageTk
import os

class SteganographyApp:
    def __init__(self, parent):
        self.parent = parent
        self.page = ttk.Frame(parent)
        parent.add(self.page, text="Hiding Text Page")

        # Variables
        self.image_path = StringVar()
        self.text_to_hide = StringVar()

        # UI Elements
        tk.Label(self.page, text="Image Steganography", font=("Helvetica", 16, "bold")).grid(row=0, columnspan=2, pady=10)

        tk.Label(self.page, text="Select Image:").grid(row=1, column=0, pady=5)
        tk.Entry(self.page, textvariable=self.image_path, state="readonly", width=30).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.page, text="Browse", command=self.browse_image).grid(row=1, column=2, pady=5)

        tk.Label(self.page, text="Enter Text to Hide:").grid(row=2, column=0, pady=5)
        tk.Entry(self.page, textvariable=self.text_to_hide, width=30).grid(row=2, column=1, pady=5)
        tk.Button(self.page, text="Hide Text", command=self.hide_text).grid(row=2, column=2, pady=5)

    def browse_image(self):
        file_path = filedialog.askopenfilename(title="Select Image File", filetypes=[("Image files", "*")])
        self.image_path.set(file_path)

    def hide_text(self):
        image_path = self.image_path.get()
        text_to_hide1 = self.text_to_hide.get()
        text_to_hide2 = text_to_hide1 + '                                                '
        
        if text_to_hide2 == '                                                ':
            text_to_hide = ""
        else:
            text_to_hide = text_to_hide2

        # Check if image_path and text_to_hide are not empty
        if not image_path or not text_to_hide:
            messagebox.showerror("Error", "Please select an image and enter text to hide.")
            return

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

            messagebox.showinfo("Steganographic Image", f"Steganographic image saved at:\n{stegano_image_path}")

        except FileNotFoundError as e:
            messagebox.showerror("Error", f"File not found: {image_path}\nError: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

class UnhideTextApp:
    def __init__(self, parent):
        self.parent = parent
        self.page = ttk.Frame(parent)
        parent.add(self.page, text="Unhiding Text Page")

        # Variables
        self.stegano_image_path = StringVar()
        self.image_preview_label = tk.Label(self.page, text="Image Preview:")
        self.file_name_label = tk.Label(self.page, text="File Name:")

        # UI Elements
        tk.Label(self.page, text="Unhide Text from Steganographic Image", font=("Helvetica", 16, "bold")).grid(pady=10)

        tk.Label(self.page, text="Select Steganographic Image:").grid(pady=5)
        tk.Entry(self.page, textvariable=self.stegano_image_path, state="readonly", width=30).grid(pady=5)
        tk.Button(self.page, text="Browse", command=self.browse_stegano_image).grid(pady=5)

        tk.Button(self.page, text="Verify Image", command=self.verify_image).grid(pady=5)

        # Hidden Text Display Area
        tk.Label(self.page, text="Hidden Text:", font=("Helvetica", 12)).grid(pady=5)
        self.hidden_text_display = tk.Entry(self.page, width=30, state="readonly")
        self.hidden_text_display.grid(pady=5)

        # Image Preview Area
        self.image_preview_label.grid(pady=5)
        self.image_preview = tk.Label(self.page)
        self.image_preview.grid(pady=5)

        # File Name Display Area
        self.file_name_label.grid(pady=5)
        self.file_name_display = tk.Label(self.page, text="")
        self.file_name_display.grid(pady=5)

    def browse_stegano_image(self):
        file_path = filedialog.askopenfilename(title="Select Steganographic Image", filetypes=[("Image files", "*")])
        self.stegano_image_path.set(file_path)
        self.clear_image_preview()

    def verify_image(self):
        stegano_image_path = self.stegano_image_path.get()

        # Check if stegano_image_path is not empty
        if not stegano_image_path:
            messagebox.showerror("Error", "Please select a steganographic image.")
            return

        try:
            # Read the steganographic image
            stegano_image = Image.open(stegano_image_path)

            # Verify if the steganographic image contains hidden text
            hidden_text = self.extract_text_from_image(stegano_image)

            if hidden_text:
                # Display the hidden text
                self.hidden_text_display.config(state="normal")
                self.hidden_text_display.delete(0, tk.END)
                self.hidden_text_display.insert(0, hidden_text)
                self.hidden_text_display.config(state="readonly")
                messagebox.showinfo("Verification", "The selected image contains hidden text.")

                # Display Image Preview
                self.display_image_preview(stegano_image)

                # Display File Name
                file_name = os.path.basename(stegano_image_path)
                self.file_name_display.config(text=file_name)
            else:
                # Show message when there is no hidden text
                self.clear_image_preview()
                self.file_name_display.config(text="")
                messagebox.showinfo("Verification", "There is no hidden text in the selected image.")

        except FileNotFoundError as e:
            messagebox.showerror("Error", f"File not found: {stegano_image_path}\nError: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def extract_text_from_image(self, image):
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

    def display_image_preview(self, image):
        # Resize image to 400x400
        image = image.resize((400, 400), Image.ANTIALIAS if hasattr(Image, "ANTIALIAS") else Image.NEAREST)
        img = ImageTk.PhotoImage(image)
        self.image_preview.config(image=img)
        self.image_preview.image = img

    def clear_image_preview(self):
        # Clear Image Preview
        self.image_preview.config(image="")
        self.image_preview.image = None

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography App")

        # Set the window size (width x height + x_offset + y_offset)
        self.root.geometry("415x800")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")

        self.steganography_app = SteganographyApp(self.notebook)
        self.unhide_text_app = UnhideTextApp(self.notebook)

        self.notebook.bind("<Button-1>", self.check_current_tab)

    def check_current_tab(self, event):
        current_tab = self.notebook.tk.call(self.notebook._w, "identify", "tab", event.x, event.y)
        if current_tab == "1":
            self.steganography_app.text_to_hide.set("")
            self.steganography_app.image_path.set("")
        elif current_tab == "2":
            self.unhide_text_app.stegano_image_path.set("")
            self.unhide_text_app.hidden_text_display.config(state="normal")
            self.unhide_text_app.hidden_text_display.delete(0, tk.END)
            self.unhide_text_app.hidden_text_display.config(state="readonly")

            # Clear Image Preview
            self.unhide_text_app.clear_image_preview()
            self.unhide_text_app.file_name_display.config(text="")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()