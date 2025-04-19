// Main JavaScript file for Cryptography Tool

// Function to update key help text based on selected algorithm
function updateKeyHelp() {
    const algorithm = document.getElementById('algorithm');
    if (!algorithm) return; // Exit if the element doesn't exist
    
    // Get all help text elements
    const aesKeyHelp = document.getElementById('aesKeyHelp');
    const desKeyHelp = document.getElementById('desKeyHelp');
    const rsaKeyHelp = document.getElementById('rsaKeyHelp');
    
    // Additional help text elements for decrypt page
    const aesDecryptHelp = document.getElementById('aesDecryptHelp');
    const desDecryptHelp = document.getElementById('desDecryptHelp');
    const rsaDecryptHelp = document.getElementById('rsaDecryptHelp');
    
    // Hide all help text elements first
    if (aesKeyHelp) aesKeyHelp.style.display = 'none';
    if (desKeyHelp) desKeyHelp.style.display = 'none';
    if (rsaKeyHelp) rsaKeyHelp.style.display = 'none';
    
    if (aesDecryptHelp) aesDecryptHelp.style.display = 'none';
    if (desDecryptHelp) desDecryptHelp.style.display = 'none';
    if (rsaDecryptHelp) rsaDecryptHelp.style.display = 'none';
    
    // Show the appropriate help text based on selected algorithm
    const selectedAlgorithm = algorithm.value;
    
    // For encrypt page
    if (selectedAlgorithm === 'aes' && aesKeyHelp) {
        aesKeyHelp.style.display = 'block';
    } else if (selectedAlgorithm === 'des' && desKeyHelp) {
        desKeyHelp.style.display = 'block';
    } else if (selectedAlgorithm === 'rsa' && rsaKeyHelp) {
        rsaKeyHelp.style.display = 'block';
    }
    
    // For decrypt page
    if (selectedAlgorithm === 'aes' && aesDecryptHelp) {
        aesDecryptHelp.style.display = 'block';
    } else if (selectedAlgorithm === 'des' && desDecryptHelp) {
        desDecryptHelp.style.display = 'block';
    } else if (selectedAlgorithm === 'rsa' && rsaDecryptHelp) {
        rsaDecryptHelp.style.display = 'block';
    }
    
    // Update the placeholder and rows for the key input on decrypt page
    const keyInput = document.getElementById('key');
    if (keyInput && selectedAlgorithm === 'rsa' && window.location.pathname.includes('decrypt')) {
        keyInput.placeholder = 'Paste the RSA private key (PEM format)';
        keyInput.rows = 6;
    } else if (keyInput && window.location.pathname.includes('decrypt')) {
        keyInput.placeholder = 'Enter the decryption key';
        keyInput.rows = 1;
    }
}

// Function to generate random keys for AES and DES
function generateRandomKey() {
    const algorithm = document.getElementById('algorithm');
    const keyInput = document.getElementById('key');
    if (!algorithm || !keyInput) return;
    
    const selectedAlgorithm = algorithm.value;
    
    if (selectedAlgorithm === 'aes') {
        // Generate 16 bytes (128 bits) random key for AES-128
        const randomKey = generateRandomString(16);
        keyInput.value = randomKey;
    } else if (selectedAlgorithm === 'des') {
        // Generate 8 bytes (64 bits) random key for DES
        const randomKey = generateRandomString(8);
        keyInput.value = randomKey;
    } else if (selectedAlgorithm === 'rsa') {
        // For RSA, inform the user that keys will be generated during encryption
        keyInput.value = '';
        alert('RSA key pair will be automatically generated when you encrypt your message.');
    }
}

// Helper function to generate random string of specified length
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

// Function to copy text to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    
    // Check if element is an input field or a code block
    if (element.tagName === 'INPUT') {
        element.select();
        document.execCommand('copy');
    } else {
        const textToCopy = element.textContent;
        
        // Create temporary textarea to copy from
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }
    
    // Show a small toast or alert that copy was successful
    alert('Copied to clipboard!');
}

// Set up event listeners when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener for algorithm selection change
    const algorithmSelect = document.getElementById('algorithm');
    if (algorithmSelect) {
        algorithmSelect.addEventListener('change', updateKeyHelp);
        // Initialize help text on page load
        updateKeyHelp();
    }
    
    // Add event listener for generate key button
    const generateKeyBtn = document.getElementById('generateKeyBtn');
    if (generateKeyBtn) {
        generateKeyBtn.addEventListener('click', generateRandomKey);
    }
});
