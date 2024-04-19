from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)

# Load the RSA key pair
with open(r"C:\Users\hp\OneDrive\Desktop\Internship report\RSA project\decrypted_private_key.pem", "r") as file:
    private_key = RSA.import_key(file.read())
with open(r"C:\Users\hp\OneDrive\Desktop\Internship report\RSA project\public_key.pem", "r") as file:
    public_key = RSA.import_key(file.read())

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message.hex()

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    encrypted_message = encrypt_message(message, public_key)
    return render_template('encrypted.html', encrypted_message=encrypted_message)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_message_hex = request.form['encrypted_message']
    encrypted_message = bytes.fromhex(encrypted_message_hex)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return render_template('decrypted.html', decrypted_message=decrypted_message)

if __name__ == '__main__':
    app.run(debug=True)
