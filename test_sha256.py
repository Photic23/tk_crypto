import hashlib
import custom_sha256

def test_sha256():
    """Test cases for the custom SHA-256 implementation."""
    test_cases = [
        b"",  # Empty string
        b"a",  # Single character
        b"abc",  # Simple string
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  # Long string
        b"The quick brown fox jumps over the lazy dog",  # Common test phrase
        b"The quick brown fox jumps over the lazy dog.",  # With period
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100  # Large input
    ]
    
    print("Testing SHA-256 Implementation:")
    print("-" * 80)
    
    for i, test in enumerate(test_cases):
        # Calculate hash using built-in hashlib
        hashlib_result = hashlib.sha256(test).hexdigest()
        
        # Calculate hash using our custom implementation
        custom_result = custom_sha256.new(test).hexdigest()
        
        # Compare results
        match = hashlib_result == custom_result
        
        print(f"Test Case {i+1}: {'PASSED' if match else 'FAILED'}")
        print(f"  Input: {test[:50]}{'...' if len(test) > 50 else ''}")
        print(f"  Expected: {hashlib_result}")
        print(f"  Got:      {custom_result}")
        print("-" * 80)
        
        if not match:
            print("WARNING: Custom SHA-256 implementation does not match hashlib!")
            return False
    
    print("All tests passed! Custom SHA-256 implementation matches hashlib.")
    return True

if __name__ == "__main__":
    test_sha256()