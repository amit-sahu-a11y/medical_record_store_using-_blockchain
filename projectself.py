from flask import Flask, render_template, request, jsonify
import datetime
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken
import pickle
import base64
from encryption_utils import generate_rsa_key_pair, encrypt_rsa, decrypt_rsa, generate_aes_key, encrypt_aes, decrypt_aes

app = Flask(__name__)

# Blockchain Class
class Blockchain:
    def _init_(self):
        self.chain = []
        self.load_chain_from_file()
        if not self.chain:
            self.create_block(proof=1, previous_hash='0', user_id=None, medical_records=None, aes_key=None)

    def create_block(self, proof, previous_hash, user_id, medical_records, aes_key):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'user_id': user_id,
            'medical_records': medical_records,
            'aes_key': aes_key
        }
        self.chain.append(block)
        self.save_chain_to_file()
        return block

    def save_chain_to_file(self):
        with open('blockchain.pkl', 'wb') as file:
            pickle.dump(self.chain, file)

    def load_chain_from_file(self):
        try:
            with open('blockchain.pkl', 'rb') as file:
                self.chain = pickle.load(file)
        except (FileNotFoundError, EOFError):
            self.chain = []

    def print_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        while True:
            hash_operation = hashlib.sha256(str(new_proof*2 - previous_proof*2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                return new_proof
            new_proof += 1

    def hash(self, block):
        # Ensure everything is JSON-serializable
        safe_block = {
            key: (value if isinstance(value, (str, int, float, type(None))) else str(value))
            for key, value in block.items()
        }
        encoded_block = json.dumps(safe_block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof*2 - previous_proof*2).encode()).hexdigest()
            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1
        return True

# Generate RSA key pair
user_private_key, user_public_key = generate_rsa_key_pair()

# Create blockchain instance
blockchain = Blockchain()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/submit_records', methods=['GET', 'POST'])
def submit_records():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user_details = request.form.get('user_details')
        medical_records = request.form.get('medical_records')

        aes_key = generate_aes_key()
        encrypted_records_aes = encrypt_aes(aes_key, medical_records)
        encrypted_aes_key = encrypt_rsa(user_public_key, aes_key)

        # Convert binary to base64 for storage
        safe_records = base64.b64encode(encrypted_records_aes).decode('utf-8')
        safe_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

        previous_block = blockchain.print_previous_block()
        previous_proof = previous_block['proof']
        proof = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)

        block = blockchain.create_block(proof, previous_hash, user_id, safe_records, safe_aes_key)

        response_data = {
            'message': 'Medical records submitted successfully',
            'user_id': user_id,
            'block_index': block['index'],
        }

        return render_template('response.html', **response_data)
    return render_template('submit_records.html')

valid_doctor_ids = {'doc1', 'doctor2'}

@app.route('/retrieve_records', methods=['GET', 'POST'])
def retrieve_records():
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        user_id = request.form.get('user_id')

        if doctor_id not in valid_doctor_ids:
            return jsonify({'error': 'Invalid doctor ID'}), 401

        user_records = []
        for block in blockchain.chain:
            if 'user_id' in block and block['user_id'] == user_id:
                try:
                    aes_key_bytes = base64.b64decode(block['aes_key'])
                    records_bytes = base64.b64decode(block['medical_records'])

                    aes_key = decrypt_rsa(user_private_key, aes_key_bytes)
                    medical_records = decrypt_aes(aes_key, records_bytes).decode('utf-8')
                except Exception as e:
                    medical_records = f"Decryption error: {str(e)}"

                user_records.append({
                    'index': block['index'],
                    'timestamp': block['timestamp'],
                    'user_id': block['user_id'],
                    'medical_records': medical_records
                })

        response_data = {
            'message': 'Medical records retrieved successfully',
            'doctor_id': doctor_id,
            'user_id': user_id,
            'medical_records': user_records
        }

        return render_template('retrieve_response.html', **response_data)
    return render_template('retrieve_records.html')

if __name__ == '_main_':
    app.run(debug=True)