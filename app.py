import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from db_helper import init_db, create_user, verify_user, save_message, get_user_messages, get_message, delete_message
from crypto_helper import encrypt_message, decrypt_message

# Tell Python not to write bytecode files in the current folder, just in case
sys_dont_write = os.environ.get("PYTHONDONTWRITEBYTECODE", "1")
os.environ["PYTHONDONTWRITEBYTECODE"] = sys_dont_write

app = Flask(__name__)
# Generate a static secret key for local development to keep sessions active across restarts
app.secret_key = "secure_encryption_decryption_secret_key_123"

# Initialize SQLite database
init_db()

def is_logged_in():
    return 'user' in session

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    error = None
    success = request.args.get('success')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            error = "Please enter both username and password."
        else:
            user = verify_user(username, password)
            if user:
                session['user'] = user
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username or password."
                
    return render_template('login.html', error=error, success=success)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        else:
            success = create_user(username, password)
            if success:
                return redirect(url_for('login', success="Account created successfully! Please log in."))
            else:
                error = "Username is already taken."
                
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user']['username'])

# --- JSON API ENDPOINTS ---

@app.route('/api/messages', methods=['GET'])
def api_get_messages():
    if not is_logged_in():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    messages = get_user_messages(session['user']['id'])
    return jsonify({'success': True, 'messages': messages})

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    if not is_logged_in():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.json
    title = data.get('title')
    message = data.get('message')
    password = data.get('password')
    secret_key = data.get('secret_key')
    
    if not title or not message or not password or not secret_key:
        return jsonify({'success': False, 'error': 'All fields (title, message, password, secret key) are required.'}), 400
        
    # Perform AES GCM encryption
    encrypted_dict = encrypt_message(message, password, secret_key)
    
    # Save encrypted message to DB
    saved = save_message(
        session['user']['id'],
        title,
        encrypted_dict['ciphertext'],
        encrypted_dict['nonce'],
        encrypted_dict['tag'],
        encrypted_dict['salt']
    )
    
    if saved:
        return jsonify({
            'success': True,
            'message': 'Message encrypted and stored safely.',
            'crypto_data': {
                'ciphertext': encrypted_dict['combined_ciphertext'],
                'tag': encrypted_dict['tag']
            }
        })
    else:
        return jsonify({'success': False, 'error': 'Database saving failed.'}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if not is_logged_in():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    data = request.json
    password = data.get('password')
    secret_key = data.get('secret_key')
    msg_id = data.get('msg_id') # If decrypting from DB
    
    if not password or not secret_key:
        return jsonify({'success': False, 'error': 'Password and Secret Key are required.'}), 400
        
    # Decrypt from database
    if msg_id:
        msg_record = get_message(int(msg_id), session['user']['id'])
        if not msg_record:
            return jsonify({'success': False, 'error': 'Message not found or access denied.'}), 404
            
        decrypted = decrypt_message(
            msg_record['ciphertext'],
            msg_record['nonce'],
            msg_record['tag'],
            msg_record['salt'],
            password,
            secret_key
        )
    # Decrypt from raw external input
    else:
        ciphertext = data.get('ciphertext')
        tag = data.get('tag')
        
        if not ciphertext or not tag:
            return jsonify({'success': False, 'error': 'Missing cryptographic parameters (ciphertext, tag).'}), 400
            
        decrypted = decrypt_message(
            ciphertext_b64=ciphertext,
            nonce_b64=None,
            tag_b64=tag,
            salt_b64=None,
            password=password,
            secret_key=secret_key
        )
        
    if decrypted is not None:
        return jsonify({'success': True, 'decrypted': decrypted})
    else:
        return jsonify({'success': False, 'error': 'Authentication failed. Incorrect Password or Secret Key.'}), 400

@app.route('/api/delete/<int:msg_id>', methods=['POST', 'DELETE'])
def api_delete_message(msg_id):
    if not is_logged_in():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
    success = delete_message(msg_id, session['user']['id'])
    if success:
        return jsonify({'success': True, 'message': 'Message deleted successfully.'})
    else:
        return jsonify({'success': False, 'error': 'Failed to delete message or unauthorized.'}), 400

if __name__ == '__main__':
    # Run application locally
    app.run(host='127.0.0.1', port=5000, debug=True)
