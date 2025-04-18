import random
import math
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import custom_sha256 as sha256  # Our custom SHA-256 implementation

# RSA Key Generation Functions
def is_prime(n, k=40):
    """Miller-Rabin primality test"""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    while True:
        # Generate a random odd number with specified bit length
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Set the highest and lowest bit
        if is_prime(p):
            return p

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(e, phi):
    """Find modular multiplicative inverse"""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return (x % phi + phi) % phi

def generate_keypair(bits=2048):
    """Generate RSA key pair"""
    # Generate two prime numbers p and q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    n = p * q  # Modulus
    phi = (p - 1) * (q - 1)  # Euler's totient function
    
    # Choose public exponent e
    e = 65537  # Common value for e
    
    # Calculate private exponent d
    d = mod_inverse(e, phi)
    
    # Public key: (n, e), Private key: (n, d)
    return (n, e), (n, d), p, q

# RSA-OAEP Functions
def mgf1(seed, length, hash_func=None):
    """Mask Generation Function based on a custom hash function"""
    # Use our custom SHA-256 implementation
    hlen = 32  # SHA-256 digest size is always 32 bytes
    if length > (2**32) * hlen:
        raise ValueError("Mask too long")
    
    T = b""
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4, byteorder='big')
        hasher = sha256.new()
        hasher.update(seed + C)
        T += hasher.digest()
        counter += 1
    
    return T[:length]

def oaep_encrypt(message, key, label=b"", hash_func=None):
    """RSA-OAEP Encryption using custom SHA-256"""
    n, e = key
    k = (n.bit_length() + 7) // 8  # Length of the RSA modulus in bytes
    
    # SHA-256 digest size is always 32 bytes
    hlen = 32
    mlen = len(message)
    
    # Check if message is too long
    if mlen > k - 2 * hlen - 2:
        raise ValueError("Message too long")
    
    # Calculate label hash using our custom SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Create padded message (DB = lHash || PS || 0x01 || M)
    PS = b'\x00' * (k - mlen - 2 * hlen - 2)
    DB = lhash + PS + b'\x01' + message
    
    # Generate random seed
    seed = os.urandom(hlen)
    
    # Calculate mask for DB using seed
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Calculate masked DB
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    
    # Calculate mask for seed using masked DB
    seedMask = mgf1(maskedDB, hlen)
    
    # Calculate masked seed
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
    
    # Construct encoded message (EM = 0x00 || maskedSeed || maskedDB)
    EM = b'\x00' + maskedSeed + maskedDB
    
    # Convert to integer and apply RSA encryption
    m_int = int.from_bytes(EM, byteorder='big')
    c_int = pow(m_int, e, n)
    
    # Convert ciphertext to bytes
    ciphertext = c_int.to_bytes(k, byteorder='big')
    
    return ciphertext

def oaep_decrypt(ciphertext, key, label=b"", hash_func=None):
    """RSA-OAEP Decryption using custom SHA-256"""
    n, d = key
    k = (n.bit_length() + 7) // 8  # Length of the RSA modulus in bytes
    
    # SHA-256 digest size is always 32 bytes
    hlen = 32
    
    # Check ciphertext length
    if len(ciphertext) != k:
        raise ValueError("Decryption error: Invalid ciphertext length")
    
    # Convert ciphertext to integer and apply RSA decryption
    c_int = int.from_bytes(ciphertext, byteorder='big')
    m_int = pow(c_int, d, n)
    
    # Convert back to bytes with proper padding
    EM = m_int.to_bytes(k, byteorder='big')
    
    # Separate components
    first_byte = EM[0]
    maskedSeed = EM[1:1+hlen]
    maskedDB = EM[1+hlen:]
    
    # Verify first byte
    if first_byte != 0:
        raise ValueError("Decryption error: Invalid padding")
    
    # Calculate seed mask
    seedMask = mgf1(maskedDB, hlen)
    
    # Recover seed
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    
    # Calculate DB mask
    dbMask = mgf1(seed, k - hlen - 1)
    
    # Recover DB
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    
    # Calculate label hash using our custom SHA-256
    hasher = sha256.new()
    hasher.update(label)
    lhash = hasher.digest()
    
    # Verify label hash
    if not DB.startswith(lhash):
        raise ValueError("Decryption error: Invalid label hash")
    
    # Find message boundary
    i = hlen
    while i < len(DB):
        if DB[i] == 0:
            i += 1
        elif DB[i] == 1:
            i += 1
            break
        else:
            raise ValueError("Decryption error: Invalid padding")
    
    # Extract message
    message = DB[i:]
    
    return message

# Key Serialization
def save_key_to_file(key, filename):
    """Save RSA key to file in hexadecimal format"""
    if len(key) == 2:
        # Regular key (n, e/d)
        n, x = key
        key_str = f"{n:x}\n{x:x}"
    elif len(key) == 4:
        # Full private key (n, d, p, q)
        n, d, p, q = key
        key_str = f"{n:x}\n{d:x}\n{p:x}\n{q:x}"
    
    with open(filename, 'w') as f:
        f.write(key_str)

def load_key_from_file(filename):
    """Load RSA key from file"""
    with open(filename, 'r') as f:
        lines = f.read().strip().split('\n')
    
    if len(lines) == 2:
        n = int(lines[0], 16)
        x = int(lines[1], 16)
        return (n, x)
    elif len(lines) == 4:
        n = int(lines[0], 16)
        d = int(lines[1], 16)
        p = int(lines[2], 16)
        q = int(lines[3], 16)
        return (n, d, p, q)
    else:
        raise ValueError("Invalid key file format")

# File Processing Functions
def encrypt_file(input_file, output_file, key_file):
    """Encrypt a file using RSA-OAEP"""
    public_key = load_key_from_file(key_file)
    n, e = public_key
    
    # Calculate maximum message size in bytes
    block_size = (n.bit_length() // 8) - 2 * 32 - 2  # 32 is the SHA-256 digest size in bytes
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            block = f_in.read(block_size)
            if not block:
                break
            
            encrypted_block = oaep_encrypt(block, public_key)
            
            # Write the length of the encrypted block followed by the block itself
            f_out.write(struct.pack('>I', len(encrypted_block)))
            f_out.write(encrypted_block)

def decrypt_file(input_file, output_file, key_file):
    """Decrypt a file using RSA-OAEP"""
    private_key = load_key_from_file(key_file)
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            # Read the length of the encrypted block
            length_bytes = f_in.read(4)
            if not length_bytes:
                break
            
            block_length = struct.unpack('>I', length_bytes)[0]
            encrypted_block = f_in.read(block_length)
            
            decrypted_block = oaep_decrypt(encrypted_block, private_key)
            f_out.write(decrypted_block)

# GUI Application
class RSA_OAEP_App:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Encryption/Decryption Tool")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create frames for each tab
        self.keygen_frame = ttk.Frame(self.notebook, padding="10")
        self.encrypt_frame = ttk.Frame(self.notebook, padding="10")
        self.decrypt_frame = ttk.Frame(self.notebook, padding="10")
        
        # Add tabs to notebook
        self.notebook.add(self.keygen_frame, text="Key Generation")
        self.notebook.add(self.encrypt_frame, text="Encryption")
        self.notebook.add(self.decrypt_frame, text="Decryption")
        
        # Set up each tab
        self.setup_keygen_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
    
    def setup_keygen_tab(self):
        # Key size options
        ttk.Label(self.keygen_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(self.keygen_frame, textvariable=self.key_size_var, state="readonly")
        key_size_combo['values'] = ('1024', '2048', '3072', '4096')
        key_size_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Output directory
        ttk.Label(self.keygen_frame, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.output_dir_var = tk.StringVar()
        ttk.Entry(self.keygen_frame, textvariable=self.output_dir_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.keygen_frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2, padx=5)
        
        # Key prefix
        ttk.Label(self.keygen_frame, text="Key Filename Prefix:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.key_prefix_var = tk.StringVar(value="rsa_key")
        ttk.Entry(self.keygen_frame, textvariable=self.key_prefix_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        
        # Generate button
        ttk.Button(self.keygen_frame, text="Generate Key Pair", command=self.generate_keys).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.keygen_progress = ttk.Progressbar(self.keygen_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.keygen_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.keygen_frame.columnconfigure(1, weight=1)
    
    def setup_encrypt_tab(self):
        # Input file
        ttk.Label(self.encrypt_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.encrypt_input_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_input_var, width=50).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_input).grid(row=0, column=2, padx=5)
        
        # Public key file
        ttk.Label(self.encrypt_frame, text="Public Key File:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.encrypt_key_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_key_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_key).grid(row=1, column=2, padx=5)
        
        # Output file
        ttk.Label(self.encrypt_frame, text="Output File:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.encrypt_output_var = tk.StringVar()
        ttk.Entry(self.encrypt_frame, textvariable=self.encrypt_output_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.encrypt_frame, text="Browse...", command=self.browse_encrypt_output).grid(row=2, column=2, padx=5)
        
        # Encrypt button
        ttk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(self.encrypt_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.encrypt_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.encrypt_frame.columnconfigure(1, weight=1)
    
    def setup_decrypt_tab(self):
        # Input file
        ttk.Label(self.decrypt_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.decrypt_input_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_input_var, width=50).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_input).grid(row=0, column=2, padx=5)
        
        # Private key file
        ttk.Label(self.decrypt_frame, text="Private Key File:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.decrypt_key_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_key_var, width=50).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_key).grid(row=1, column=2, padx=5)
        
        # Output file
        ttk.Label(self.decrypt_frame, text="Output File:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.decrypt_output_var = tk.StringVar()
        ttk.Entry(self.decrypt_frame, textvariable=self.decrypt_output_var, width=50).grid(row=2, column=1, sticky=tk.W+tk.E, padx=5)
        ttk.Button(self.decrypt_frame, text="Browse...", command=self.browse_decrypt_output).grid(row=2, column=2, padx=5)
        
        # Decrypt button
        ttk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt).grid(row=3, column=1, pady=20)
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(self.decrypt_frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.decrypt_progress.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, pady=10)
        
        # Configure grid
        self.decrypt_frame.columnconfigure(1, weight=1)
    
    # File browsing functions
    def browse_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_dir_var.set(directory)
    
    def browse_encrypt_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.encrypt_input_var.set(filename)
            # Automatically set output filename
            output_filename = filename + ".enc"
            self.encrypt_output_var.set(output_filename)
    
    def browse_encrypt_key(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.encrypt_key_var.set(filename)
    
    def browse_encrypt_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".enc")
        if filename:
            self.encrypt_output_var.set(filename)
    
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if filename:
            self.decrypt_input_var.set(filename)
            # Automatically set output filename (remove .enc if present)
            if filename.endswith(".enc"):
                output_filename = filename[:-4]
            else:
                output_filename = filename + ".dec"
            self.decrypt_output_var.set(output_filename)
    
    def browse_decrypt_key(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.decrypt_key_var.set(filename)
    
    def browse_decrypt_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.decrypt_output_var.set(filename)
    
    # Core functionality
    def generate_keys(self):
        # Get parameters
        key_size = int(self.key_size_var.get())
        output_dir = self.output_dir_var.get()
        key_prefix = self.key_prefix_var.get()
        
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return
        
        # Start progress bar
        self.keygen_progress.start()
        self.status_var.set("Generating keys... This may take a while.")
        self.root.update_idletasks()
        
        # Generate keys in a separate thread to avoid freezing the UI
        self.root.after(100, self.do_generate_keys, key_size, output_dir, key_prefix)
    
    def do_generate_keys(self, key_size, output_dir, key_prefix):
        try:
            # Generate key pair
            public_key, private_key, p, q = generate_keypair(key_size)
            
            # Save keys to files
            public_key_file = os.path.join(output_dir, f"{key_prefix}_public.txt")
            private_key_file = os.path.join(output_dir, f"{key_prefix}_private.txt")
            
            save_key_to_file(public_key, public_key_file)
            save_key_to_file((private_key[0], private_key[1], p, q), private_key_file)
            
            # Stop progress bar
            self.keygen_progress.stop()
            self.status_var.set("Keys generated successfully")
            
            messagebox.showinfo("Success", f"Keys generated and saved to:\n{public_key_file}\n{private_key_file}")
        
        except Exception as e:
            # Stop progress bar
            self.keygen_progress.stop()
            self.status_var.set("Error generating keys")
            
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
    
    def encrypt(self):
        # Get parameters
        input_file = self.encrypt_input_var.get()
        key_file = self.encrypt_key_var.get()
        output_file = self.encrypt_output_var.get()
        
        if not input_file or not key_file or not output_file:
            messagebox.showerror("Error", "Please select all required files")
            return
        
        # Start progress bar
        self.encrypt_progress.start()
        self.status_var.set("Encrypting... This may take a while.")
        self.root.update_idletasks()
        
        # Encrypt in a separate thread
        self.root.after(100, self.do_encrypt, input_file, key_file, output_file)
    
    def do_encrypt(self, input_file, key_file, output_file):
        try:
            # Encrypt file
            encrypt_file(input_file, output_file, key_file)
            
            # Stop progress bar
            self.encrypt_progress.stop()
            self.status_var.set("File encrypted successfully")
            
            messagebox.showinfo("Success", f"File encrypted and saved to:\n{output_file}")
        
        except Exception as e:
            # Stop progress bar
            self.encrypt_progress.stop()
            self.status_var.set("Error encrypting file")
            
            messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")
    
    def decrypt(self):
        # Get parameters
        input_file = self.decrypt_input_var.get()
        key_file = self.decrypt_key_var.get()
        output_file = self.decrypt_output_var.get()
        
        if not input_file or not key_file or not output_file:
            messagebox.showerror("Error", "Please select all required files")
            return
        
        # Start progress bar
        self.decrypt_progress.start()
        self.status_var.set("Decrypting... This may take a while.")
        self.root.update_idletasks()
        
        # Decrypt in a separate thread
        self.root.after(100, self.do_decrypt, input_file, key_file, output_file)
    
    def do_decrypt(self, input_file, key_file, output_file):
        try:
            # Decrypt file
            decrypt_file(input_file, output_file, key_file)
            
            # Stop progress bar
            self.decrypt_progress.stop()
            self.status_var.set("File decrypted successfully")
            
            messagebox.showinfo("Success", f"File decrypted and saved to:\n{output_file}")
        
        except Exception as e:
            # Stop progress bar
            self.decrypt_progress.stop()
            self.status_var.set("Error decrypting file")
            
            messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")

# Main function
def main():
    root = tk.Tk()
    app = RSA_OAEP_App(root)
    root.mainloop()

if __name__ == "__main__":
    main()