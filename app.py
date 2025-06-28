from flask import Flask, render_template, request, jsonify, send_file
from PIL import Image
import numpy as np
import io
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
import math

app = Flask(__name__)

def hide_message(image, message, password=None):
    img_array = np.array(image)
    
    if password:
        iv = os.urandom(16)
        key = hashlib.sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        message_bytes = iv + ciphertext
    else:
        message_bytes = message.encode()
    
    binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
    binary_message += '1111111111111110'  # Delimiter
    
    if len(binary_message) > img_array.size:
        raise ValueError("Pesan terlalu besar untuk gambar")
    
    flat = img_array.flatten()
    for i in range(len(binary_message)):
        current_pixel = flat[i]
        new_pixel = (current_pixel & 0xFE) | int(binary_message[i])
        flat[i] = np.uint8(max(0, min(255, new_pixel)))
    
    img_array = flat.reshape(img_array.shape)
    return Image.fromarray(img_array)

def extract_message(image, password=None):
    img_array = np.array(image)
    flat = img_array.flatten()
    
    binary_message = ''
    delimiter = '1111111111111110'
    found = False
    
    for i in range(flat.size):
        lsb = str(flat[i] & 1)
        binary_message += lsb
        
        if len(binary_message) >= 16 and binary_message[-16:] == delimiter:
            binary_message = binary_message[:-16]
            found = True
            break
    
    if not found:
        return "Tidak ditemukan pesan rahasia"
    
    message_bytes = bytearray()
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            message_bytes.append(int(byte, 2))
    
    if password:
        if len(message_bytes) < 16:
            return "Pesan terlalu pendek"
        
        iv = message_bytes[:16]
        ciphertext = message_bytes[16:]
        
        try:
            key = hashlib.sha256(password.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Gagal mendekripsi: {str(e)}"
    
    return message_bytes.decode('utf-8', errors='ignore')

def visualize_lsb(image):
    """Membuat visualisasi bit LSB dari gambar"""
    img_array = np.array(image)
    # Ambil hanya bit LSB dan skala ke 0-255
    lsb_visual = (img_array & 1) * 255
    return Image.fromarray(lsb_visual.astype(np.uint8))

def calculate_psnr(original, stego):
    # Convert images to numpy arrays
    original_arr = np.array(original).astype(np.float64)
    stego_arr = np.array(stego).astype(np.float64)
    
    # Calculate MSE (Mean Squared Error)
    mse = np.mean((original_arr - stego_arr) ** 2)
    
    if mse == 0:
        return float('inf')
    
    max_pixel = 255.0
    psnr = 20 * math.log10(max_pixel / math.sqrt(mse))
    return psnr

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hide', methods=['POST'])
def hide():
    try:
        # Get form data
        image_file = request.files['image']
        message = request.form['message']
        password = request.form.get('password', '')
        
        # Open image
        image = Image.open(image_file)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Hide message
        stego_image = hide_message(image, message, password)

        psnr_value = calculate_psnr(image, stego_image)
        
        # Save to byte stream
        img_byte_arr = io.BytesIO()
        stego_image.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)
        
        # Convert to base64 for preview
        base64_image = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
        
        original_lsb = visualize_lsb(image)
        stego_lsb = visualize_lsb(stego_image)
        
        # Simpan visualisasi ke BytesIO
        def image_to_base64(img):
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            img_byte_arr.seek(0)
            return base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
        
        
        # Contoh perubahan pixel untuk 5 pixel pertama
        original_array = np.array(image)
        stego_array = np.array(stego_image)
        n_samples = 5
        pixel_examples = []
        
        # Ambil 5 pixel pertama (channel R saja)
        for i in range(n_samples):
            # Ambil nilai R dari pixel ke-i
            r_original = original_array[0, i, 0]
            r_stego = stego_array[0, i, 0]
            
            # Konversi ke biner
            bin_original = format(r_original, '08b')
            bin_stego = format(r_stego, '08b')
            
            # Ambil bit pesan (LSB stego)
            message_bit = bin_stego[7]
            
            pixel_examples.append({
                'pixel_index': i + 1,
                'original_bin': bin_original,
                'message_bit': message_bit,
                'stego_bin': bin_stego
            })
        
        return jsonify({
            'success': True,
            'stego_image': base64_image,
            'original_width': image.width,
            'original_height': image.height,
            'message_length': len(message),
            'original_lsb': image_to_base64(original_lsb),
            'stego_lsb': image_to_base64(stego_lsb),
            'pixel_examples': pixel_examples,
            'psnr': psnr_value
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/extract', methods=['POST'])
def extract():
    try:
        # Get form data
        image_file = request.files['image']
        password = request.form.get('password', '')
        
        # Open image
        image = Image.open(image_file)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Extract message
        message = extract_message(image, password)
        
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # pakai PORT dari Railway
    app.run(host="0.0.0.0", port=port)
