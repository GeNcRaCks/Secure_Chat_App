from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import hmac
from datetime import datetime

def generate_rsa_keys():
    """Generate RSA key pair (2048 bits)"""
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    """Encrypt AES key with RSA public key"""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def decrypt_aes_key(encrypted_key, private_key):
    """Decrypt AES key with RSA private key"""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

def generate_hmac_key(aes_key):
    """Generate HMAC key from AES key"""
    # Use SHA-256 of AES key to create HMAC key
    hmac_key = hashlib.sha256(aes_key).digest()
    return hmac_key

def encrypt_message(message, aes_key):
    """Encrypt message with AES-256-CBC and add HMAC-SHA256 integrity check"""
    # Generate random IV for each message
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Add timestamp to message
    timestamp = datetime.now().strftime("%H:%M:%S")
    full_message = f"{message}||{timestamp}"
    
    # Encrypt
    ciphertext = cipher.encrypt(pad(full_message.encode('utf-8'), AES.block_size))
    
    # Generate HMAC for integrity verification
    hmac_key = generate_hmac_key(aes_key)
    data_to_hmac = iv + ciphertext
    message_hmac = hmac.new(hmac_key, data_to_hmac, hashlib.sha256).digest()
    
    # Combine IV + ciphertext + HMAC
    encrypted_data = iv + ciphertext + message_hmac
    return base64.b64encode(encrypted_data)

def decrypt_message(encrypted_data, aes_key):
    """Decrypt message with AES-256-CBC and verify HMAC-SHA256 integrity"""
    try:
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_data)
        
        # Check minimum length
        if len(encrypted_data) < 48:  # 16 IV + at least 16 ciphertext + 32 HMAC
            raise ValueError("❌ Message too short for decryption")
        
        # Extract IV, ciphertext, and HMAC
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:-32]  # -32 for SHA-256 HMAC
        received_hmac = encrypted_data[-32:]
        
        # Generate HMAC for verification
        hmac_key = generate_hmac_key(aes_key)
        data_to_hmac = iv + ciphertext
        calculated_hmac = hmac.new(hmac_key, data_to_hmac, hashlib.sha256).digest()
        
        # Verify HMAC (integrity check)
        if not hmac.compare_digest(received_hmac, calculated_hmac):
            raise ValueError("❌ INTEGRITY CHECK FAILED: Message may have been tampered with!")
        
        # Decrypt
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        # Split message and timestamp
        parts = decrypted.decode('utf-8').split('||')
        
        if len(parts) < 2:
            raise ValueError("❌ Invalid message format")
        
        # Return message, timestamp, and integrity status
        return parts[0], parts[1], True
        
    except ValueError as e:
        # Re-raise integrity errors
        raise e
    except Exception as e:
        # For other decryption errors
        raise ValueError(f"❌ DECRYPTION FAILED: {str(e)}")

def get_key_fingerprint(key):
    """Generate fingerprint for key verification"""
    if isinstance(key, bytes):
        key_bytes = key
    else:
        key_bytes = key.export_key()
    
    sha256 = hashlib.sha256(key_bytes).hexdigest()
    return ':'.join([sha256[i:i+2] for i in range(0, 10, 2)]) + "..."

def get_message_hash(message):
    """Generate SHA-256 hash of message for display"""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()[:16] + "..."

def get_encryption_details(aes_key, rsa_key=None):
    """Get detailed encryption information"""
    hmac_key = generate_hmac_key(aes_key)
    
    details = {
        "AES Key": f"{len(aes_key)*8}-bit ({aes_key.hex()[:16]}...)",
        "AES Mode": "CBC",
        "Key Exchange": "RSA-2048",
        "Padding": "PKCS7",
        "IV Size": "16 bytes (random per message)",
        "Integrity Check": "HMAC-SHA256",
        "HMAC Key": f"{hmac_key.hex()[:16]}...",
        "Hash Algorithm": "SHA-256"
    }
    
    if rsa_key:
        details["RSA Key Size"] = "2048 bits"
        details["RSA Fingerprint"] = get_key_fingerprint(rsa_key)
    
    return details

def verify_message_integrity(encrypted_data, aes_key):
    """Verify message integrity without decryption"""
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        
        if len(encrypted_data) < 48:  # Minimum: 16 IV + 16 ciphertext + 16 HMAC
            return False, "Message too short"
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:-32]
        received_hmac = encrypted_data[-32:]
        
        hmac_key = generate_hmac_key(aes_key)
        data_to_hmac = iv + ciphertext
        calculated_hmac = hmac.new(hmac_key, data_to_hmac, hashlib.sha256).digest()
        
        if hmac.compare_digest(received_hmac, calculated_hmac):
            return True, "✅ Integrity verified (HMAC-SHA256)"
        else:
            return False, "❌ Integrity check failed"
            
    except Exception as e:
        return False, f"❌ Verification error: {str(e)}"

def tamper_with_message(encrypted_data):
    """Simulate message tampering for testing (DO NOT USE IN PRODUCTION)"""
    encrypted_data = base64.b64decode(encrypted_data)
    
    if len(encrypted_data) > 32:
        # Tamper with the ciphertext (not the HMAC)
        tampered = bytearray(encrypted_data)
        # Change one byte in the middle of ciphertext
        if len(tampered) > 48:
            tampered[32] ^= 0xFF  # Flip all bits in this byte
        
        return base64.b64encode(bytes(tampered))
    
    return base64.b64encode(encrypted_data)
