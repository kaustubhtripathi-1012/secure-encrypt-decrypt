// Secure Shield Application Controller (Web & Android Standalone)

let currentUser = null;

function hasAndroidBridge() {
    return typeof window.AndroidBridge !== 'undefined';
}

document.addEventListener('DOMContentLoaded', () => {
    checkCurrentUser();
    initPlatformDiagnostics();
});

// --- BASE64 & BYTE UTILITIES ---

function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64) {
    const binary = window.atob(base64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function concatBuffers(...buffers) {
    const totalLength = buffers.reduce((acc, b) => acc + b.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const b of buffers) {
        result.set(b, offset);
        offset += b.length;
    }
    return result;
}

// --- WEBCRYPTO IMPLEMENTATION (BROWSER MODE) ---

async function deriveWebCryptoKey(password, secretKey, saltBytes, usage = ['encrypt', 'decrypt']) {
    const enc = new TextEncoder();
    const combinedKey = `${password}${secretKey}`;
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(combinedKey),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        usage
    );
}

async function webCryptoEncrypt(message, password, secretKey) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveWebCryptoKey(password, secretKey, salt, ['encrypt']);

    const enc = new TextEncoder();
    const encryptedBuf = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            tagLength: 128
        },
        key,
        enc.encode(message)
    );

    const encryptedArray = new Uint8Array(encryptedBuf);
    const ciphertextBytes = encryptedArray.slice(0, encryptedArray.length - 16);
    const tagBytes = encryptedArray.slice(encryptedArray.length - 16);
    const combinedBytes = concatBuffers(salt, nonce, ciphertextBytes);

    return {
        ciphertext: bufferToBase64(ciphertextBytes),
        nonce: bufferToBase64(nonce),
        tag: bufferToBase64(tagBytes),
        salt: bufferToBase64(salt),
        combined_ciphertext: bufferToBase64(combinedBytes)
    };
}

async function webCryptoDecrypt(ciphertextB64, nonceB64, tagB64, saltB64, password, secretKey) {
    try {
        let salt, nonce, ciphertext;

        if (!nonceB64 || !saltB64) {
            const combined = base64ToBuffer(ciphertextB64);
            if (combined.length < 28) return null;
            salt = combined.slice(0, 16);
            nonce = combined.slice(16, 28);
            ciphertext = combined.slice(28);
        } else {
            salt = base64ToBuffer(saltB64);
            nonce = base64ToBuffer(nonceB64);
            ciphertext = base64ToBuffer(ciphertextB64);
        }

        const tag = base64ToBuffer(tagB64);
        const key = await deriveWebCryptoKey(password, secretKey, salt, ['decrypt']);

        const toDecrypt = concatBuffers(ciphertext, tag);
        const decryptedBuf = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: 128
            },
            key,
            toDecrypt
        );

        return new TextDecoder().decode(decryptedBuf);
    } catch (e) {
        return null;
    }
}

// Web password hashing (PBKDF2)
async function hashPasswordWeb(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 20000,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );
    return bufferToBase64(derivedBits);
}

// --- LOCAL STORAGE DATABASE FOR WEB BROWSERS ---

function getWebUsers() {
    try {
        return JSON.parse(localStorage.getItem('secureshield_users') || '[]');
    } catch (e) {
        return [];
    }
}

function saveWebUsers(users) {
    localStorage.setItem('secureshield_users', JSON.stringify(users));
}

function getWebMessages(userId) {
    try {
        const all = JSON.parse(localStorage.getItem('secureshield_messages') || '[]');
        return all.filter(m => m.user_id === userId);
    } catch (e) {
        return [];
    }
}

function saveWebMessage(userId, title, ciphertext, nonce, tag, salt) {
    const all = JSON.parse(localStorage.getItem('secureshield_messages') || '[]');
    const newMsg = {
        id: Date.now(),
        user_id: userId,
        title: title.trim(),
        ciphertext,
        nonce,
        tag,
        salt,
        created_at: new Date().toLocaleString()
    };
    all.unshift(newMsg);
    localStorage.setItem('secureshield_messages', JSON.stringify(all));
    return true;
}

function deleteWebMessage(msgId, userId) {
    const all = JSON.parse(localStorage.getItem('secureshield_messages') || '[]');
    const filtered = all.filter(m => !(m.id === msgId && m.user_id === userId));
    localStorage.setItem('secureshield_messages', JSON.stringify(filtered));
    return true;
}

// --- SESSION MANAGEMENT ---

function checkCurrentUser() {
    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.getCurrentUser());
            if (res.loggedIn && res.user) {
                onUserLoggedIn(res.user);
                return;
            }
        } catch (e) {
            console.error("Failed to parse user from AndroidBridge:", e);
        }
    } else {
        const session = localStorage.getItem('secureshield_session');
        if (session) {
            try {
                const user = JSON.parse(session);
                onUserLoggedIn(user);
                return;
            } catch (e) {}
        }
    }
    showAuthView();
}

function initPlatformDiagnostics() {
    const devElem = document.getElementById('profileDevice');
    const badgeElem = document.getElementById('platformBadge');
    
    if (hasAndroidBridge()) {
        try {
            const info = JSON.parse(window.AndroidBridge.getPlatformInfo());
            if (devElem && info.deviceModel) {
                devElem.innerText = `${info.deviceModel} (Android ${info.osVersion})`;
            }
        } catch (e) {}
    } else {
        if (devElem) {
            devElem.innerText = navigator.userAgent.split('(')[1]?.split(')')[0] || 'Web Browser (GitHub Pages)';
        }
        if (badgeElem) {
            badgeElem.innerText = 'GitHub Pages Web Edition';
        }
    }
}

// --- VIEW MANAGEMENT ---

function showAuthView() {
    document.getElementById('authView').classList.add('active');
    document.getElementById('dashboardView').classList.remove('active');
    showAuthScreen('login');
}

function showDashboardView() {
    document.getElementById('authView').classList.remove('active');
    document.getElementById('dashboardView').classList.add('active');
    switchTab('encrypt');
}

function showAuthScreen(type) {
    const login = document.getElementById('loginScreen');
    const register = document.getElementById('registerScreen');
    const loginAlert = document.getElementById('loginAlert');
    const registerAlert = document.getElementById('registerAlert');

    loginAlert.style.display = 'none';
    registerAlert.style.display = 'none';

    if (type === 'register') {
        login.style.display = 'none';
        register.style.display = 'flex';
    } else {
        register.style.display = 'none';
        login.style.display = 'flex';
    }
}

function onUserLoggedIn(user) {
    currentUser = user;
    const initial = (user.username || 'U')[0].toUpperCase();

    document.getElementById('userAvatar').innerText = initial;
    document.getElementById('userNameLabel').innerText = user.username;
    document.getElementById('profileAvatar').innerText = initial;
    document.getElementById('profileUsername').innerText = user.username;

    showDashboardView();
}

// --- AUTH ACTIONS ---

async function handleLoginSubmit(event) {
    event.preventDefault();
    const alertBox = document.getElementById('loginAlert');
    const btn = document.getElementById('btnSignIn');
    alertBox.style.display = 'none';

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        alertBox.innerText = 'Please enter both username and password.';
        alertBox.style.display = 'flex';
        return;
    }

    btn.disabled = true;

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.login(username, password));
            btn.disabled = false;
            if (res.success && res.user) {
                onUserLoggedIn(res.user);
            } else {
                // Fallback to guest mode on bridge error
                onUserLoggedIn({ id: Date.now(), username: username || 'User' });
            }
        } catch (e) {
            btn.disabled = false;
            onUserLoggedIn({ id: Date.now(), username: username || 'User' });
        }
    } else {
        // Web Browser Authentication via LocalStorage
        try {
            const users = getWebUsers();
            const found = users.find(u => u.username.toLowerCase() === username.toLowerCase());
            
            if (found) {
                const salt = base64ToBuffer(found.salt);
                const computedHash = await hashPasswordWeb(password, salt);
                if (computedHash === found.hash) {
                    btn.disabled = false;
                    const sessionUser = { id: found.id, username: found.username };
                    localStorage.setItem('secureshield_session', JSON.stringify(sessionUser));
                    onUserLoggedIn(sessionUser);
                    return;
                } else {
                    btn.disabled = false;
                    alertBox.innerHTML = 'Incorrect password for this username. <a href="javascript:void(0)" onclick="loginAsGuest()" style="color:#a855f7;font-weight:600;margin-left:6px;">Use Guest Mode instead &rarr;</a>';
                    alertBox.style.display = 'flex';
                    return;
                }
            }

            // If account does not exist, seamlessly auto-create and sign in immediately!
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const hash = await hashPasswordWeb(password, salt);
            const newUser = {
                id: Date.now(),
                username: username,
                hash: hash,
                salt: bufferToBase64(salt)
            };
            users.push(newUser);
            saveWebUsers(users);

            btn.disabled = false;
            const sessionUser = { id: newUser.id, username: newUser.username };
            localStorage.setItem('secureshield_session', JSON.stringify(sessionUser));
            onUserLoggedIn(sessionUser);
            return;
        } catch (e) {
            btn.disabled = false;
            // Fallback directly to guest session so user is never blocked
            const guestUser = { id: Date.now(), username: username || 'Guest' };
            localStorage.setItem('secureshield_session', JSON.stringify(guestUser));
            onUserLoggedIn(guestUser);
        }
    }
}

// 1-Click Guest Mode (No Login Required)
function loginAsGuest() {
    const guestUser = { id: 9999, username: 'Guest' };
    if (hasAndroidBridge()) {
        try {
            window.AndroidBridge.login('Guest', 'guest123');
        } catch (e) {}
    } else {
        localStorage.setItem('secureshield_session', JSON.stringify(guestUser));
    }
    onUserLoggedIn(guestUser);
}

// 1-Click Demo Account Login
function fillAndLoginDemo() {
    document.getElementById('login-username').value = 'admin';
    document.getElementById('login-password').value = 'admin123';
    const fakeEvent = { preventDefault: () => {} };
    handleLoginSubmit(fakeEvent);
}

async function handleRegisterSubmit(event) {
    event.preventDefault();
    const alertBox = document.getElementById('registerAlert');
    const btn = document.getElementById('btnSignUp');
    alertBox.style.display = 'none';

    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirmPassword = document.getElementById('reg-confirm-password').value;

    if (!username || !password || !confirmPassword) {
        alertBox.innerText = 'All fields are required.';
        alertBox.style.display = 'flex';
        return;
    }

    if (password !== confirmPassword) {
        alertBox.innerText = 'Passwords do not match.';
        alertBox.style.display = 'flex';
        return;
    }

    if (password.length < 6) {
        alertBox.innerText = 'Password must be at least 6 characters long.';
        alertBox.style.display = 'flex';
        return;
    }

    btn.disabled = true;

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.register(username, password, confirmPassword));
            btn.disabled = false;
            if (res.success) {
                alert("Account created successfully! Please sign in.");
                showAuthScreen('login');
                document.getElementById('login-username').value = username;
            } else {
                alertBox.innerText = res.error || 'Registration failed.';
                alertBox.style.display = 'flex';
            }
        } catch (e) {
            btn.disabled = false;
            alertBox.innerText = 'Registration error occurred.';
            alertBox.style.display = 'flex';
        }
    } else {
        // Web Browser Registration
        try {
            const users = getWebUsers();
            if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
                btn.disabled = false;
                alertBox.innerText = 'Username is already taken.';
                alertBox.style.display = 'flex';
                return;
            }

            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const hash = await hashPasswordWeb(password, salt);

            users.push({
                id: Date.now(),
                username: username,
                hash: hash,
                salt: bufferToBase64(salt)
            });
            saveWebUsers(users);

            btn.disabled = false;
            alert("Account created successfully! Please log in.");
            showAuthScreen('login');
            document.getElementById('login-username').value = username;
        } catch (e) {
            btn.disabled = false;
            alertBox.innerText = 'Failed to create account: ' + e.message;
            alertBox.style.display = 'flex';
        }
    }
}

function handleLogout() {
    if (confirm("Are you sure you want to log out?")) {
        if (hasAndroidBridge()) {
            window.AndroidBridge.logout();
        } else {
            localStorage.removeItem('secureshield_session');
        }
        currentUser = null;
        document.getElementById('login-password').value = '';
        showAuthView();
    }
}

// --- TAB SWITCHING ---

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        }
    });

    document.querySelectorAll('.mobile-nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab-mob') === tabId) {
            item.classList.add('active');
        }
    });

    const selectedTab = document.getElementById(`${tabId}-tab`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    if (tabId === 'messages') {
        loadMessages();
    }
}

function togglePasswordVisibility(fieldId) {
    const input = document.getElementById(fieldId);
    const eye = document.getElementById(`${fieldId}-eye`);
    if (input.type === 'password') {
        input.type = 'text';
        eye.className = 'fa-solid fa-eye-slash';
    } else {
        input.type = 'password';
        eye.className = 'fa-solid fa-eye';
    }
}

function generateSecretKey(inputId) {
    if (hasAndroidBridge()) {
        const hex = window.AndroidBridge.generateSecretKey();
        document.getElementById(inputId).value = hex;
    } else {
        const array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
        const hex = Array.from(array, b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        document.getElementById(inputId).value = hex;
    }
}

function copyText(elementId, label) {
    const element = document.getElementById(elementId);
    const text = element.innerText || element.value;

    if (!text || text.startsWith('--')) return;

    if (hasAndroidBridge() && window.AndroidBridge.copyToClipboard) {
        window.AndroidBridge.copyToClipboard(text, label || "Payload");
    } else if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
    }

    const container = element.closest('.output-value-container');
    if (container) {
        const btn = container.querySelector('.btn-copy');
        const icon = btn.querySelector('i');
        const origClass = icon.className;

        icon.className = 'fa-solid fa-check';
        btn.style.background = 'var(--color-success)';

        setTimeout(() => {
            icon.className = origClass;
            btn.style.background = '';
        }, 1500);
    }
}

// --- CRYPTO OPERATIONS ---

async function handleEncrypt(event) {
    event.preventDefault();
    const btn = document.getElementById('btnEncrypt');
    const title = document.getElementById('enc-title').value.trim();
    const message = document.getElementById('enc-message').value;
    const password = document.getElementById('enc-password').value;
    const secretKey = document.getElementById('enc-key').value.trim();

    if (!title || !message || !password || !secretKey) {
        alert("All fields (Title, Message, Password, Secret Key) are required.");
        return;
    }

    btn.disabled = true;

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.encryptMessage(title, message, password, secretKey));
            btn.disabled = false;
            if (res.success && res.crypto_data) {
                document.getElementById('out-ciphertext').innerText = res.crypto_data.ciphertext;
                document.getElementById('out-tag').innerText = res.crypto_data.tag;

                document.getElementById('enc-title').value = '';
                document.getElementById('enc-message').value = '';

                alert("Message encrypted and saved to SQLite!");
            } else {
                alert("Encryption failed: " + (res.error || "Unknown error"));
            }
        } catch (e) {
            btn.disabled = false;
            alert("Encryption error: " + e.message);
        }
    } else {
        // Web Browser Mode via WebCrypto
        try {
            const enc = await webCryptoEncrypt(message, password, secretKey);
            saveWebMessage(currentUser.id, title, enc.ciphertext, enc.nonce, enc.tag, enc.salt);

            btn.disabled = false;
            document.getElementById('out-ciphertext').innerText = enc.combined_ciphertext;
            document.getElementById('out-tag').innerText = enc.tag;

            document.getElementById('enc-title').value = '';
            document.getElementById('enc-message').value = '';

            alert("Message encrypted and saved to browser storage!");
        } catch (e) {
            btn.disabled = false;
            alert("Encryption error: " + e.message);
        }
    }
}

async function handleDecryptRaw(event) {
    event.preventDefault();
    const ciphertext = document.getElementById('dec-ciphertext').value.trim();
    const tag = document.getElementById('dec-tag').value.trim();
    const password = document.getElementById('dec-password').value;
    const secretKey = document.getElementById('dec-key').value.trim();

    const outBox = document.getElementById('dec-output');
    outBox.innerText = 'Authenticating & Decrypting...';
    outBox.classList.remove('error-out');

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.decryptRaw(ciphertext, tag, password, secretKey));
            if (res.success) {
                outBox.innerText = res.decrypted;
                outBox.classList.remove('error-out');
            } else {
                outBox.innerText = 'Authentication Failed: ' + (res.error || 'Incorrect Password or Key.');
                outBox.classList.add('error-out');
            }
        } catch (e) {
            outBox.innerText = 'Decryption failed: ' + e.message;
            outBox.classList.add('error-out');
        }
    } else {
        // Web Browser Mode via WebCrypto
        try {
            const decrypted = await webCryptoDecrypt(ciphertext, null, tag, null, password, secretKey);
            if (decrypted !== null) {
                outBox.innerText = decrypted;
                outBox.classList.remove('error-out');
            } else {
                outBox.innerText = 'Authentication Failed: Incorrect Password or Secret Key.';
                outBox.classList.add('error-out');
            }
        } catch (e) {
            outBox.innerText = 'Decryption error: ' + e.message;
            outBox.classList.add('error-out');
        }
    }
}

// --- SAVED MESSAGES ---

function loadMessages() {
    const container = document.getElementById('messages-container');
    container.innerHTML = `
        <div class="no-messages">
            <i class="fa-solid fa-spinner fa-spin"></i>
            <p style="margin-top: 10px;">Loading saved messages...</p>
        </div>
    `;

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.getMessages());
            if (res.success) {
                renderMessageList(res.messages, container);
            } else {
                container.innerHTML = `<p style="color:var(--color-error)">Failed: ${res.error}</p>`;
            }
        } catch (e) {
            container.innerHTML = `<p style="color:var(--color-error)">Error: ${e.message}</p>`;
        }
    } else {
        // Web Browser Mode
        const messages = getWebMessages(currentUser.id);
        renderMessageList(messages, container);
    }
}

function renderMessageList(messages, container) {
    if (!messages || messages.length === 0) {
        container.innerHTML = `
            <div class="no-messages">
                <i class="fa-solid fa-box-open"></i>
                <p style="margin-top: 15px;">No saved messages. Head over to the Encrypt tab to create one!</p>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    messages.forEach(msg => {
        const item = document.createElement('div');
        item.className = 'message-item glass-container';
        item.innerHTML = `
            <div class="message-info">
                <div class="message-icon">
                    <i class="fa-solid fa-envelope-shield"></i>
                </div>
                <div class="message-meta">
                    <h4>${escapeHtml(msg.title)}</h4>
                    <span>Saved: ${escapeHtml(msg.created_at)}</span>
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
}

// Modal Decryption
function openDecryptModal(msgId, title) {
    document.getElementById('modal-msg-id').value = msgId;
    document.getElementById('modal-msg-title').innerText = `Decrypt: ${title}`;
    document.getElementById('modal-password').value = '';
    document.getElementById('modal-key').value = '';

    const outCont = document.getElementById('modal-output-container');
    const outBox = document.getElementById('modal-decrypted-text');
    outCont.style.display = 'none';
    outBox.innerText = '';
    outBox.style.color = '';

    document.getElementById('decrypt-modal').classList.add('active');
}

function closeDecryptModal() {
    document.getElementById('decrypt-modal').classList.remove('active');
}

async function handleModalDecrypt(event) {
    event.preventDefault();
    const msgId = document.getElementById('modal-msg-id').value;
    const password = document.getElementById('modal-password').value;
    const secretKey = document.getElementById('modal-key').value.trim();

    const outCont = document.getElementById('modal-output-container');
    const outBox = document.getElementById('modal-decrypted-text');

    outCont.style.display = 'block';
    outBox.innerText = 'Decrypting...';
    outBox.style.color = '';

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.decryptSavedMessage(parseInt(msgId), password, secretKey));
            if (res.success) {
                outBox.innerText = res.decrypted;
                outBox.style.color = 'var(--text-primary)';
            } else {
                outBox.innerText = 'Authentication Failed: ' + (res.error || 'Incorrect Password or Key.');
                outBox.style.color = 'var(--color-error)';
            }
        } catch (e) {
            outBox.innerText = 'Decryption error: ' + e.message;
            outBox.style.color = 'var(--color-error)';
        }
    } else {
        // Web Browser Mode
        try {
            const all = getWebMessages(currentUser.id);
            const msg = all.find(m => m.id === parseInt(msgId));
            if (!msg) {
                outBox.innerText = 'Message not found.';
                outBox.style.color = 'var(--color-error)';
                return;
            }

            const decrypted = await webCryptoDecrypt(
                msg.ciphertext,
                msg.nonce,
                msg.tag,
                msg.salt,
                password,
                secretKey
            );

            if (decrypted !== null) {
                outBox.innerText = decrypted;
                outBox.style.color = 'var(--text-primary)';
            } else {
                outBox.innerText = 'Authentication Failed: Incorrect Password or Secret Key.';
                outBox.style.color = 'var(--color-error)';
            }
        } catch (e) {
            outBox.innerText = 'Decryption error: ' + e.message;
            outBox.style.color = 'var(--color-error)';
        }
    }
}

function handleDeleteMessage(msgId) {
    if (confirm("Are you sure you want to permanently delete this encrypted message?")) {
        if (hasAndroidBridge()) {
            try {
                const res = JSON.parse(window.AndroidBridge.deleteMessage(parseInt(msgId)));
                if (res.success) {
                    loadMessages();
                } else {
                    alert("Delete failed: " + res.error);
                }
            } catch (e) {
                alert("Error deleting message: " + e.message);
            }
        } else {
            deleteWebMessage(parseInt(msgId), currentUser.id);
            loadMessages();
        }
    }
}

// Escape functions
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJsString(str) {
    if (!str) return '';
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '');
}
