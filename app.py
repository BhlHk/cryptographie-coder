import os
import base64
import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))

# Cache for storing common cipher instances
from functools import lru_cache

# Cryptography Functions
def normalize_key_aes(key):
    """Normalize key to valid AES key lengths (16, 24, or 32 bytes)"""
    if len(key) < 16:
        return key.ljust(16, '0').encode('utf-8')
    elif len(key) > 16 and len(key) < 24:
        return key.ljust(24, '0').encode('utf-8')
    elif len(key) > 24:
        return key.ljust(32, '0')[:32].encode('utf-8')
    return key.encode('utf-8')

def encrypt_aes(message, key):
    """
    Encrypt message using AES-CBC mode
    
    Args:
        message (str): Plain text message
        key (str): Encryption key
        
    Returns:
        str: Base64 encoded ciphertext+IV
    """
    try:
        key_bytes = normalize_key_aes(key)
        message_bytes = message.encode('utf-8')
        
        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        
        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_message = pad(message_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        # Combine IV and ciphertext and encode to base64
        result = base64.b64encode(iv + ciphertext).decode('utf-8')
        return result
    except Exception as e:
        logging.error(f"AES encryption error: {e}")
        raise ValueError(f"AES encryption error: {e}")

def decrypt_aes(ciphertext_b64, key):
    """
    Decrypt AES-encrypted message
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext+IV
        key (str): Decryption key
        
    Returns:
        str: Decrypted plain text
    """
    try:
        key_bytes = normalize_key_aes(key)
        
        # Decode base64
        ciphertext_with_iv = base64.b64decode(ciphertext_b64)
        
        # Extract IV (first block) and ciphertext
        iv = ciphertext_with_iv[:AES.block_size]
        ciphertext = ciphertext_with_iv[AES.block_size:]
        
        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        padded_message = cipher.decrypt(ciphertext)
        message = unpad(padded_message, AES.block_size)
        
        return message.decode('utf-8')
    except Exception as e:
        logging.error(f"AES decryption error: {e}")
        raise ValueError(f"AES decryption error: {e}")

def encrypt_des(message, key):
    """
    Encrypt message using DES-CBC mode
    
    Args:
        message (str): Plain text message
        key (str): Encryption key
        
    Returns:
        str: Base64 encoded ciphertext+IV
    """
    try:
        # Ensure key is exactly 8 bytes
        if len(key) < 8:
            key = key.ljust(8, '0')
        key_bytes = key[:8].encode('utf-8')
        message_bytes = message.encode('utf-8')
        
        # Generate random IV
        iv = get_random_bytes(DES.block_size)
        
        # Create cipher
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_message = pad(message_bytes, DES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        # Combine IV and ciphertext and encode to base64
        result = base64.b64encode(iv + ciphertext).decode('utf-8')
        return result
    except Exception as e:
        logging.error(f"DES encryption error: {e}")
        raise ValueError(f"DES encryption error: {e}")

def decrypt_des(ciphertext_b64, key):
    """
    Decrypt DES-encrypted message
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext+IV
        key (str): Decryption key
        
    Returns:
        str: Decrypted plain text
    """
    try:
        # Ensure key is exactly 8 bytes
        if len(key) < 8:
            key = key.ljust(8, '0')
        key_bytes = key[:8].encode('utf-8')
        
        # Decode base64
        ciphertext_with_iv = base64.b64decode(ciphertext_b64)
        
        # Extract IV (first block) and ciphertext
        iv = ciphertext_with_iv[:DES.block_size]
        ciphertext = ciphertext_with_iv[DES.block_size:]
        
        # Create cipher
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Decrypt and unpad
        padded_message = cipher.decrypt(ciphertext)
        message = unpad(padded_message, DES.block_size)
        
        return message.decode('utf-8')
    except Exception as e:
        logging.error(f"DES decryption error: {e}")
        raise ValueError(f"DES decryption error: {e}")

def generate_rsa_keys():
    """
    Generate a new RSA key pair
    
    Returns:
        tuple: (private_key_pem, public_key_pem)
    """
    try:
        # Generate key pair
        key = RSA.generate(2048)
        
        # Extract private and public keys in PEM format
        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')
        
        return private_key_pem, public_key_pem
    except Exception as e:
        logging.error(f"RSA key generation error: {e}")
        raise ValueError(f"RSA key generation error: {e}")

def encrypt_rsa(message, public_key_pem):
    """
    Encrypt message using RSA public key
    
    Args:
        message (str): Plain text message
        public_key_pem (str): Public key in PEM format
        
    Returns:
        str: Base64 encoded ciphertext
    """
    try:
        # Import public key
        public_key = RSA.import_key(public_key_pem)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(public_key)
        
        # Encrypt message
        message_bytes = message.encode('utf-8')
        ciphertext = cipher.encrypt(message_bytes)
        
        # Encode to base64
        result = base64.b64encode(ciphertext).decode('utf-8')
        return result
    except Exception as e:
        logging.error(f"RSA encryption error: {e}")
        raise ValueError(f"RSA encryption error: {e}")

def decrypt_rsa(ciphertext_b64, private_key_pem):
    """
    Decrypt RSA-encrypted message
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext
        private_key_pem (str): Private key in PEM format
        
    Returns:
        str: Decrypted plain text
    """
    try:
        # Import private key
        private_key = RSA.import_key(private_key_pem)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(private_key)
        
        # Decode base64 and decrypt
        ciphertext = base64.b64decode(ciphertext_b64)
        message = cipher.decrypt(ciphertext)
        
        return message.decode('utf-8')
    except Exception as e:
        logging.error(f"RSA decryption error: {e}")
        raise ValueError(f"RSA decryption error: {e}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        message = request.form.get('message', '')
        if not message:
            flash('Please enter a message to encrypt', 'danger')
            return redirect(url_for('index'))
        
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '')
        
        if algorithm == 'aes':
            if not key:
                flash('Please provide a key for AES encryption', 'danger')
                return redirect(url_for('index'))
            result = encrypt_aes(message, key)
            return render_template('result.html', 
                                  result=result, 
                                  key=key, 
                                  algorithm=algorithm, 
                                  operation="Encryption",
                                  original_text=message)
        
        elif algorithm == 'des':
            if not key:
                flash('Please provide a key for DES encryption', 'danger')
                return redirect(url_for('index'))
            result = encrypt_des(message, key)
            return render_template('result.html', 
                                  result=result, 
                                  key=key, 
                                  algorithm=algorithm, 
                                  operation="Encryption",
                                  original_text=message)
        
        elif algorithm == 'rsa':
            # If key is provided, use it as public key, otherwise generate new keys
            if key:
                try:
                    # Verify key format
                    _ = RSA.import_key(key)
                    result = encrypt_rsa(message, key)
                    return render_template('result.html', 
                                        result=result, 
                                        key=key, 
                                        algorithm=algorithm, 
                                        operation="Encryption",
                                        original_text=message)
                except Exception:
                    flash('Invalid RSA public key format', 'danger')
                    return redirect(url_for('index'))
            else:
                private_key, public_key = generate_rsa_keys()
                result = encrypt_rsa(message, public_key)
                return render_template('result.html', 
                                      result=result, 
                                      key=public_key, 
                                      private_key=private_key,
                                      algorithm=algorithm, 
                                      operation="Encryption",
                                      original_text=message)
        else:
            flash('Please select a valid encryption algorithm', 'danger')
            return redirect(url_for('index'))
    
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/decrypt')
def decrypt_page():
    return render_template('decrypt.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        ciphertext = request.form.get('ciphertext', '')
        if not ciphertext:
            flash('Please enter a ciphertext to decrypt', 'danger')
            return redirect(url_for('decrypt_page'))
        
        algorithm = request.form.get('algorithm')
        key = request.form.get('key', '')
        
        if not key:
            flash('Please provide a key for decryption', 'danger')
            return redirect(url_for('decrypt_page'))
        
        if algorithm == 'aes':
            result = decrypt_aes(ciphertext, key)
        elif algorithm == 'des':
            result = decrypt_des(ciphertext, key)
        elif algorithm == 'rsa':
            result = decrypt_rsa(ciphertext, key)
        else:
            flash('Please select a valid decryption algorithm', 'danger')
            return redirect(url_for('decrypt_page'))
        
        return render_template('result.html', 
                              result=result, 
                              key=key, 
                              algorithm=algorithm, 
                              operation="Decryption",
                              original_text=ciphertext)
    
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('decrypt_page'))
    except Exception as e:
        flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return redirect(url_for('decrypt_page'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
