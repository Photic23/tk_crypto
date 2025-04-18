def _right_rotate(n, b):
    """Right rotate a 32-bit integer n by b bits."""
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

def _pad_message(message):
    """Pad the message according to SHA-256 standards.
    
    1. Append a single '1' bit
    2. Append K '0' bits, where K is the minimum number >= 0 such that 
       (message length in bits) + 1 + K + 64 is a multiple of 512
    3. Append the message length as a 64-bit big-endian integer
    """
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Initial message length in bits
    message_length = len(message) * 8
    
    # Append the bit '1' (+ 7 '0' bits to complete a byte)
    message = bytearray(message) + b'\x80'
    
    # Append '0' bits until the message length (in bits) mod 512 = 448
    # This ensures total length is multiple of 64 bytes (512 bits) after adding 8 bytes (64 bits)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Append the original message length as a 64-bit big-endian integer
    message += message_length.to_bytes(8, byteorder='big')
    
    return message

def sha256(message):
    """Implement SHA-256 hash function from scratch."""
    
    # Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    
    # Initialize array of round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Pad the message to ensure its length is a multiple of 512 bits
    padded_message = _pad_message(message)
    
    # Process the message in 512-bit (64-byte) chunks
    for chunk_start in range(0, len(padded_message), 64):
        chunk = padded_message[chunk_start:chunk_start + 64]
        
        # Create a 64-entry message schedule array w[0..63] of 32-bit words
        w = [0] * 64
        
        # Copy chunk into first 16 words of message schedule array
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big')
        
        # Extend the first 16 words into the remaining 48 words of w[16..63]
        for i in range(16, 64):
            s0 = _right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        # Initialize working variables to current hash value
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # Compression function main loop
        for i in range(64):
            S1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Add the compressed chunk to the current hash value
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Produce the final hash value (big-endian)
    digest = b''
    digest += h0.to_bytes(4, byteorder='big')
    digest += h1.to_bytes(4, byteorder='big')
    digest += h2.to_bytes(4, byteorder='big')
    digest += h3.to_bytes(4, byteorder='big')
    digest += h4.to_bytes(4, byteorder='big')
    digest += h5.to_bytes(4, byteorder='big')
    digest += h6.to_bytes(4, byteorder='big')
    digest += h7.to_bytes(4, byteorder='big')
    
    return digest

# Create a class with the same interface as Python's hashlib
class SHA256:
    def __init__(self, message=b''):
        self.message = bytearray() if message == b'' else bytearray(message)
    
    def update(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        self.message += message
        return self
    
    def digest(self):
        return sha256(self.message)
    
    def hexdigest(self):
        return self.digest().hex()

# Function to match hashlib's interface
def new(message=b''):
    return SHA256(message)