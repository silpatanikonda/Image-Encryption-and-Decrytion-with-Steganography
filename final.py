import tkinter as tk
from tkinter import ttk, filedialog, messagebox, StringVar
from PIL import Image, ImageTk
import os
import subprocess
import sys

class FinalApplication(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("ImageCryptorHub Application")
        print("ImageCryptorHub Application Main Menu")

        # Create a notebook (tabs)
        # Set the window size (width x height + x_offset + y_offset)
        self.geometry("510x320+100+50")
        self.original="510x320+100+50"
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # Create tabs
        self.encryption_tab = ttk.Frame(self.notebook)
        self.decryption_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)

        # Add tabs to the notebook with updated names
        self.notebook.add(self.encryption_tab, text="Steganography & Encryption")
        self.notebook.add(self.decryption_tab, text="Steganalysis & Decryption")
        self.notebook.add(self.about_tab, text="App's Insight")
        
        # Create dictionaries to store navigation history for each tab
        self.encryption_history = []
        self.decryption_history = []

        # Initialize encryption and decryption tabs
        self.init_encryption_tab()
        self.init_decryption_tab()
        self.init_about_tab()
        self.image_path=""
        
    def init_encryption_tab(self):
        # Create buttons for Encryption tab
        self.steganography_button = tk.Button(self.encryption_tab, text="Image Steganography", command=self.run_hide)
        self.steganography_button.pack(pady=10)
        self.encryption_button = tk.Button(self.encryption_tab, text="Image Encryption", command=self.show_encryption_options)
        self.encryption_button.pack(pady=10)
        # Close Button
        self.close_button1 = tk.Button(self.encryption_tab, text="Close App", command=self.close_enc_tab)
        self.close_button1.pack(pady=10)
        self.copyright_text = tk.Label(self.encryption_tab, text="Image Encryption & Decryption with Steganography & Steganalysis\n© CyberSecurity-5")
        self.copyright_text.pack(side="bottom", pady=10)

    def init_decryption_tab(self):
        # Create buttons for Decryption tab
        self.steganalysis_button = tk.Button(self.decryption_tab, text="Image Steganalysis", command=self.run_unhide)
        self.steganalysis_button.pack(pady=10)
        self.decryption_button = tk.Button(self.decryption_tab, text="Image Decryption", command=self.show_decryption_options)
        self.decryption_button.pack(pady=10)
        # Close Button
        self.close_button2 = tk.Button(self.decryption_tab, text="Close App", command=self.close_dec_tab)
        self.close_button2.pack(pady=10)
        self.copyright_text = tk.Label(self.decryption_tab, text="Image Encryption & Decryption with Steganography & Steganalysis\n© CyberSecurity-5")
        self.copyright_text.pack(side="bottom", pady=10)
        
    def show_encryption_options(self):
        #print("Image Encryption Menu")
        # Create a new frame for encryption options
        self.encryption_options_frame = ttk.Frame(self.encryption_tab)
        self.encryption_options_frame.pack(fill="both", expand=True)

        # Clear previous buttons
        self.steganography_button.pack_forget()
        self.encryption_button.pack_forget()
        self.close_button1.pack_forget()

        # Create buttons for encryption algorithms
        self.aes_button = tk.Button(self.encryption_options_frame, text="AES Algorithm Encryption", command=self.run_aes_enc)
        self.aes_button.pack(pady=5)
        self.des_button = tk.Button(self.encryption_options_frame, text="3DES Algorithm Encryption", command=self.run_des_enc)
        self.des_button.pack(pady=5)
        self.rsa_button = tk.Button(self.encryption_options_frame, text="RSA Algorithm Encryption", command=self.run_rsa_enc)
        self.rsa_button.pack(pady=5)
        
        # Create back button for Encryption tab
        self.encryption_back_button = tk.Button(self.encryption_options_frame, text="Back", command=self.back_to_main_encryption)
        self.encryption_back_button.pack(pady=5)
        
        # Close Button
        self.close_button = tk.Button(self.encryption_options_frame, text="Close App", command=self.close_enc2_tab)
        self.close_button.pack(pady=10)

        # Store current page in history
        self.encryption_history.append(self.encryption_options_frame)
        
    def select_image_decryption(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff;*.raw")])
        if path:
            self.entry_encrypted_path.delete(0, tk.END)
            self.entry_encrypted_path.insert(0, path)
            self.display_selected_image_info()
            
    def detect_algorithm(self):
        encrypted_path = self.entry_encrypted_path.get()
        image_path=encrypted_path
        folder_name = os.path.basename(os.path.dirname(encrypted_path))
        image_name = os.path.basename(encrypted_path)
        if "aes" in folder_name.lower() or "aes" in image_name.lower():
            algorithm = "AES Algorithm"
            #messagebox.showinfo("Algorithm Detected", "AES Algorithm is used for Encryption.")
            self.after(1500, lambda: self.run_aes_dec(image_path))
        elif "des" in folder_name.lower() or "des" in image_name.lower():
            algorithm = "3DES Algorithm"
            #messagebox.showinfo("Algorithm Detected", "3DES Algorithm is used for Encryption.")
            self.after(1500, lambda: self.run_des_dec(image_path))
        elif "rsa" in folder_name.lower() or "rsa" in image_name.lower():
            algorithm = "RSA Algorithm"
            #messagebox.showinfo("Algorithm Detected", "RSA Algorithm is used for Encryption.")
            self.after(1500, lambda: self.run_rsa_dec(image_path))
        else:
            algorithm = "Unknown Algorithm"
            messagebox.showinfo("Algorithm Not Detected", "Unable to detect the algorithm used for encryption.")
        self.display_algorithm_detected(algorithm)
             
    def display_algorithm_detected(self,algorithm):
        algo = algorithm
        self.label_algorithm_detected.config(text=f"{algo} is used for Encryption")
            
    def display_selected_image_info(self):
        image_path = self.entry_encrypted_path.get()
        self.label_selected_image_decryption.config(text=f"Selected Image:\nName: {os.path.basename(image_path)}\nPath: {image_path}\n\n**Selected Image is in Encrypted Image File Format,\n is not Supported to Open!**")
        
    def show_decryption_options(self):
        #print("Image Decryption Menu")
        # Create a new frame for encryption options
        self.decryption_options_frame = ttk.Frame(self.decryption_tab)
        self.decryption_options_frame.pack(fill="both", expand=True)
        self.geometry("560x540+100+50")

        # Clear previous buttons
        self.steganalysis_button.pack_forget()
        self.decryption_button.pack_forget()
        self.close_button2.pack_forget()
        
        label_encrypted_path = tk.Label(self.decryption_options_frame, text="Select Encrypted Image:")
        label_encrypted_path.pack(pady=10,padx=5)

        self.entry_encrypted_path = tk.Entry(self.decryption_options_frame, width=30)
        self.entry_encrypted_path.pack(pady=10,padx=5)

        button_browse_encrypted = tk.Button(self.decryption_options_frame, text="Browse", command=self.select_image_decryption)
        button_browse_encrypted.pack(pady=10,padx=5)
        
        self.label_selected_image_decryption = tk.Label(self.decryption_options_frame, text="")
        self.label_selected_image_decryption.pack(pady=10,padx=5)
        
        self.label_algorithm_detected = tk.Label(self.decryption_options_frame, text="")
        self.label_algorithm_detected.pack(pady=10,padx=5)
        
        # Create detect algorithm button
        detect_algorithm_button = tk.Button(self.decryption_options_frame, text="Detect Algorithm", command=self.detect_algorithm)
        detect_algorithm_button.pack(pady=10,padx=5)
        
        self.refresh_button = tk.Button(self.decryption_options_frame, text="Refresh", command=self.refresh_img_dec)
        self.refresh_button.pack(pady=10, padx=5)
        
        # Create back button for Encryption tab
        self.decryption_back_button = tk.Button(self.decryption_options_frame, text="Back", command=self.back_to_main_decryption)
        self.decryption_back_button.pack(pady=5)
        
        # Close Button
        self.close_button = tk.Button(self.decryption_options_frame, text="Close App", command=self.close_dec2_tab)
        self.close_button.pack(pady=10)

        # Store current page in history
        self.decryption_history.append(self.decryption_options_frame)
        
    def refresh_img_dec(self):
        self.entry_encrypted_path.delete(0,tk.END)
        self.label_selected_image_decryption.config(text="")
        self.label_algorithm_detected.config(text="")
        
    def init_about_tab(self):
        #print("ImageCryptorHub App's Insight")
        # About tab content
        about_text = "*About Final Application:-* \n\nExperience cutting-edge image encryption and decryption with the Final Application. In today's digital age, ensuring the security of sensitive information is paramount. \n\nOur application utilizes advanced steganography techniques to embed and extract data within images, offering a secure and discreet method of communication. Whether you're safeguarding personal files or transmitting confidential data, trust the Final Application to keep your information private and protected.\n\nKey Features:- \n*Steganography:* Conceal sensitive data within images to ensure privacy and security.\n*Encryption:* Protect your data with advanced encryption algorithms, including AES, 2-Key 3DES, and RSA.\n*Decryption:* Decrypt hidden information from steganographic images effortlessly.\n*User-Friendly Interface:* Navigate through encryption and decryption processes with ease, thanks to the clean and intuitive interface.\n\nDeveloped by: CyberSecurity-5 \nVersion: 1.0 \nCopyright © 2024 All Rights Reserved.\n\nImage Encryption & Decryption with Steganography & Steganalysis."
        about_scroll = tk.Scrollbar(self.about_tab, orient="vertical")
        about_scroll.pack(side="right", fill="y")
        # Close Button
        self.close_button = tk.Button(self.about_tab, text="Close App", command=self.close_about_tab)
        self.close_button.pack(side="bottom", pady=10)
        self.about_text = tk.Text(self.about_tab, wrap="word", yscrollcommand=about_scroll.set, font=("Helvetica",12))
        self.about_text.pack(fill="both", expand=True)
        about_scroll.config(command=self.about_text.yview)
        self.about_text.insert("1.0", about_text)
        #self.about_text.window_create(tk.END, window=self.close_about_tab)
        self.copyright_text = tk.Label(self.about_tab, text="Image Encryption & Decryption with Steganography & Steganalysis\n© CyberSecurity-5")
        self.copyright_text.pack(side="bottom", pady=10)
    
    def back_to_main_encryption(self):
        # Destroy the encryption options frame
        self.encryption_options_frame.destroy()

        # Display previous buttons
        self.steganography_button.pack(pady=10)
        self.encryption_button.pack(pady=10)
        self.close_button1.pack(pady=10)

        # Remove current page from history
        self.encryption_history.pop()
        
    def back_to_main_decryption(self):
        # Destroy the encryption options frame
        self.decryption_options_frame.destroy()
        self.geometry(self.original)

        # Display previous buttons
        self.steganalysis_button.pack(pady=10)
        self.decryption_button.pack(pady=10)
        self.close_button2.pack(pady=10)

        # Remove current page from history
        self.decryption_history.pop()

    def clear_encryption_options(self):
        try:
            self.encryption_back_button.destroy()
            self.aes_button.destroy()
            self.des_button.destroy()
            self.rsa_button.destroy()
            self.close_button.destroy()
        except AttributeError:
            pass
            
    def clear_decryption_options(self):
        try:
            self.decryption_back_button.destroy()
            self.aes_button.destroy()
            self.des_button.destroy()
            self.rsa_button.destroy()
            self.close_button.destroy()
        except AttributeError:
            pass
            
    def run_hide(self):
        subprocess.run(["python3","hide.py"])
        
    def run_unhide(self):
        subprocess.run(["python3","unhide.py"])
        
    def run_aes_enc(self):
        subprocess.run(["python3","1.py"])
        
    def run_des_enc(self):
        subprocess.run(["python3","des_enc.py"])
        
    def run_rsa_enc(self):
        subprocess.run(["python3","rsa_enc.py"])
        
    def run_aes_dec(self, image_path):
        subprocess.run(["python3","main.py", image_path])
        
    def run_des_dec(self, image_path):
        subprocess.run(["python3","des_dec.py", image_path])
        
    def run_rsa_dec(self, image_path):
        subprocess.run(["python3","rsa_dec.py", image_path])
        
    def run_dec(self):
        subprocess.run(["python3","dec.py"])
        
    def close_enc_tab(self):
        self.encryption_tab.quit()
        
    def close_enc2_tab(self):
        self.encryption_options_frame.quit()
        
    def close_dec2_tab(self):
        self.decryption_options_frame.quit()
        
    def close_dec_tab(self):
        self.decryption_tab.quit()
        
    def close_about_tab(self):
        self.about_tab.quit()
        

if __name__ == "__main__":
    app = FinalApplication()
    app.mainloop()