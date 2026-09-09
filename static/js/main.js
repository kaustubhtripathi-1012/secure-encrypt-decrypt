// Tab Switching Logic (Responsive)
function switchTab(tabId) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from sidebar nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        }
    });

    // Remove active class from mobile nav items
    document.querySelectorAll('.mobile-nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab-mob') === tabId) {
            item.classList.add('active');
        }
    });

    // Show selected tab content
    const selectedTab = document.getElementById(`${tabId}-tab`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Special trigger: Load messages if entering the messages tab
    if (tabId === 'messages') {
        loadMessages();
    }
}

// Password Visibility Toggle
function togglePasswordVisibility(fieldId) {
    const input = document.getElementById(fieldId);
    const eye = document.getElementById(`${fieldId}-eye`);
    if (input.type === 'password') {
        input.type = 'text';
        eye.classList.remove('fa-eye');
        eye.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        eye.classList.remove('fa-eye-slash');
        eye.classList.add('fa-eye');
    }
}

// Generate Secure Cryptographic Random 256-bit Key (in Hex)
function generateSecretKey(inputId) {
    const array = new Uint8Array(16); // 16 bytes = 128 bits of entropy (produces 32 hex chars)
    window.crypto.getRandomValues(array);
    const hexKey = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
    document.getElementById(inputId).value = hexKey;
}

// Copy Text to Clipboard with Visual Feedback
function copyText(elementId) {
    const element = document.getElementById(elementId);
    let text = element.innerText || element.value;
    
    // Clean placeholder messages
    if (text.startsWith('--')) return;

    navigator.clipboard.writeText(text).then(() => {
        // Find copy button related to this element
        const container = element.closest('.output-value-container');
        if (container) {
            const btn = container.querySelector('.btn-copy');
            const icon = btn.querySelector('i');
            
            // Toggle to success icon
            icon.className = 'fa-solid fa-check';
            btn.style.background = 'var(--color-success)';
            
            setTimeout(() => {
                icon.className = 'fa-regular fa-copy';
                btn.style.background = '';
            }, 1500);
        }
    }).catch(err => {
        console.error('Could not copy text: ', err);
    });
}

// --- API ACTIONS ---

// Encrypt and Save message
function handleEncrypt(event) {
    event.preventDefault();
    
    const title = document.getElementById('enc-title').value;
    const message = document.getElementById('enc-message').value;
    const password = document.getElementById('enc-password').value;
    const secretKey = document.getElementById('enc-key').value;
    
    fetch('/api/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, message, password, secret_key: secretKey })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            document.getElementById('out-ciphertext').innerText = data.crypto_data.ciphertext;
            document.getElementById('out-tag').innerText = data.crypto_data.tag;
            
            // Clear inputs
            document.getElementById('enc-title').value = '';
            document.getElementById('enc-message').value = '';
            
            alert('Message encrypted and saved successfully in database!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(err => {
        console.error('Encryption failed:', err);
        alert('Encryption request failed.');
    });
}

// Decrypt Raw pasted payload
function handleDecryptRaw(event) {
    event.preventDefault();
    
    const ciphertext = document.getElementById('dec-ciphertext').value;
    const tag = document.getElementById('dec-tag').value;
    const password = document.getElementById('dec-password').value;
    const secretKey = document.getElementById('dec-key').value;
    
    const outBox = document.getElementById('dec-output');
    outBox.innerText = 'Decrypting...';
    outBox.classList.remove('error-out');
    
    fetch('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ciphertext,
            tag,
            password,
            secret_key: secretKey
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            outBox.innerText = data.decrypted;
        } else {
            outBox.innerText = 'Authentication Failed: ' + data.error;
            outBox.classList.add('error-out');
        }
    })
    .catch(err => {
        console.error('Decryption failed:', err);
        outBox.innerText = 'Decryption failed. Please check payload formatting.';
        outBox.classList.add('error-out');
    });
}

// Load List of Saved Messages
function loadMessages() {
    const container = document.getElementById('messages-container');
    container.innerHTML = `
        <div class="no-messages">
            <i class="fa-solid fa-spinner fa-spin"></i>
            <p style="margin-top: 10px;">Loading saved messages...</p>
        </div>
    `;
    
    fetch('/api/messages')
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            if (data.messages.length === 0) {
                container.innerHTML = `
                    <div class="no-messages">
                        <i class="fa-solid fa-box-open"></i>
                        <p style="margin-top: 15px;">No saved messages. Head over to Encrypt tab to create one!</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            data.messages.forEach(msg => {
                const item = document.createElement('div');
                item.className = 'message-item glass-container';
                
                // Formatted date string
                const date = new Date(msg.created_at + 'Z').toLocaleString();
                
                item.innerHTML = `
                    <div class="message-info">
                        <div class="message-icon">
                            <i class="fa-solid fa-envelope-shield"></i>
                        </div>
                        <div class="message-meta">
                            <h4>${escapeHtml(msg.title)}</h4>
                            <span>Saved: ${date}</span>
                        </div>
                    </div>
                    <div class="message-actions">
                        <button class="btn-icon btn-icon-decrypt" onclick="openDecryptModal(${msg.id}, '${escapeJsString(msg.title)}')" title="Decrypt Message">
                            <i class="fa-solid fa-unlock-keyhole"></i>
                        </button>
                        <button class="btn-icon btn-icon-delete" onclick="handleDeleteMessage(${msg.id})" title="Delete Message">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                `;
                container.appendChild(item);
            });
        } else {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fa-solid fa-triangle-exclamation" style="color: var(--color-error)"></i>
                    <p style="margin-top: 15px; color: var(--color-error)">Failed to load messages: ${data.error}</p>
                </div>
            `;
        }
    })
    .catch(err => {
        console.error('Failed to load messages:', err);
        container.innerHTML = `
            <div class="no-messages">
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--color-error)"></i>
                <p style="margin-top: 15px; color: var(--color-error)">Request failed.</p>
            </div>
        `;
    });
}

// Delete Message Action
function handleDeleteMessage(msgId) {
    if (confirm('Are you sure you want to permanently delete this encrypted message?')) {
        fetch(`/api/delete/${msgId}`, {
            method: 'POST'
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                loadMessages();
            } else {
                alert('Deletion failed: ' + data.error);
            }
        })
        .catch(err => {
            console.error('Delete request failed:', err);
            alert('Request failed.');
        });
    }
}

// --- DECRYPT MODAL MANAGEMENT ---

function openDecryptModal(msgId, title) {
    // Reset modal inputs
    document.getElementById('modal-msg-id').value = msgId;
    document.getElementById('modal-msg-title').innerText = `Decrypt: ${title}`;
    document.getElementById('modal-password').value = '';
    document.getElementById('modal-key').value = '';
    
    // Hide decrypted output
    document.getElementById('modal-output-container').style.display = 'none';
    document.getElementById('modal-decrypted-text').innerText = '';
    
    // Display modal
    document.getElementById('decrypt-modal').classList.add('active');
}

function closeDecryptModal() {
    document.getElementById('decrypt-modal').classList.remove('active');
}

// Handle submit inside modal
function handleModalDecrypt(event) {
    event.preventDefault();
    
    const msgId = document.getElementById('modal-msg-id').value;
    const password = document.getElementById('modal-password').value;
    const secretKey = document.getElementById('modal-key').value;
    
    const outputContainer = document.getElementById('modal-output-container');
    const outputText = document.getElementById('modal-decrypted-text');
    
    fetch('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            msg_id: msgId,
            password,
            secret_key: secretKey
        })
    })
    .then(res => res.json())
    .then(data => {
        outputContainer.style.display = 'block';
        if (data.success) {
            outputText.innerText = data.decrypted;
            outputText.style.color = 'var(--text-primary)';
            outputText.style.borderColor = 'rgba(16, 185, 129, 0.2)';
            outputText.style.background = 'rgba(16, 185, 129, 0.05)';
        } else {
            outputText.innerText = 'Authentication Failed: ' + data.error;
            outputText.style.color = 'var(--color-error)';
            outputText.style.borderColor = 'rgba(239, 68, 68, 0.2)';
            outputText.style.background = 'rgba(239, 68, 68, 0.05)';
        }
    })
    .catch(err => {
        console.error('Modal decryption failed:', err);
        outputContainer.style.display = 'block';
        outputText.innerText = 'Request failed.';
        outputText.style.color = 'var(--color-error)';
    });
}

// --- UTILITIES ---

function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeJsString(str) {
    return str.replace(/'/g, "\\'").replace(/"/g, '\\"');
}

// Close modal when clicking outside of modal card
window.addEventListener('click', function(event) {
    const modal = document.getElementById('decrypt-modal');
    if (event.target === modal) {
        closeDecryptModal();
    }
});
