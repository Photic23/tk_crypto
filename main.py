import tkinter as tk
from rsa_oaep import RSA_OAEP_App
import custom_sha256  # Import our custom SHA-256 implementation

if __name__ == "__main__":
    # Print a message about using custom SHA-256 implementation
    print("Using custom SHA-256 implementation for RSA-OAEP")
    
    # Start the GUI application
    root = tk.Tk()
    app = RSA_OAEP_App(root)
    root.mainloop()