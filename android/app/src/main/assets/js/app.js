// Secure Shield Android Application Controller

let currentUser = null;

// Utility: Check if running inside Android APK
function hasAndroidBridge() {
    return typeof window.AndroidBridge !== 'undefined';
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    checkCurrentUser();
    initPlatformDiagnostics();
});

// Check if user is already logged in
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
    }
    showAuthView();
}

function initPlatformDiagnostics() {
    if (hasAndroidBridge()) {
        try {
            const info = JSON.parse(window.AndroidBridge.getPlatformInfo());
            const devElem = document.getElementById('profileDevice');
            if (devElem && info.deviceModel) {
                devElem.innerText = `${info.deviceModel} (Android ${info.osVersion})`;
            }
        } catch (e) {
            console.error("Failed to get platform info:", e);
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

function handleLoginSubmit(event) {
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
                alertBox.innerText = res.error || 'Invalid credentials.';
                alertBox.style.display = 'flex';
            }
        } catch (e) {
            btn.disabled = false;
            alertBox.innerText = 'Login error occurred.';
            alertBox.style.display = 'flex';
        }
    } else {
        // Fallback for browser preview
        btn.disabled = false;
        onUserLoggedIn({ id: 1, username: username });
    }
}

function handleRegisterSubmit(event) {
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
                if (window.AndroidBridge.showToast) {
                    window.AndroidBridge.showToast("Account created successfully! Please sign in.");
                } else {
                    alert("Account created successfully! Please sign in.");
                }
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
        btn.disabled = false;
        alert("Registration simulated (Browser Mode).");
        showAuthScreen('login');
    }
}

function handleLogout() {
    if (confirm("Are you sure you want to log out?")) {
        if (hasAndroidBridge()) {
            window.AndroidBridge.logout();
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

// Password Visibility Toggle
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

// Generate Random Secret Key
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

// Copy to Clipboard with Feedback
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

function handleEncrypt(event) {
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

                if (window.AndroidBridge.showToast) {
                    window.AndroidBridge.showToast("Message encrypted and saved to SQLite!");
                } else {
                    alert("Message encrypted and saved successfully!");
                }
            } else {
                alert("Encryption failed: " + (res.error || "Unknown error"));
            }
        } catch (e) {
            btn.disabled = false;
            alert("Encryption error: " + e.message);
        }
    } else {
        btn.disabled = false;
        alert("Running in browser demo mode.");
    }
}

function handleDecryptRaw(event) {
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
    }
}

// --- SAVED MESSAGES ---

function loadMessages() {
    const container = document.getElementById('messages-container');
    container.innerHTML = `
        <div class="no-messages">
            <i class="fa-solid fa-spinner fa-spin"></i>
            <p style="margin-top: 10px;">Loading saved messages from SQLite...</p>
        </div>
    `;

    if (hasAndroidBridge()) {
        try {
            const res = JSON.parse(window.AndroidBridge.getMessages());
            if (res.success) {
                if (!res.messages || res.messages.length === 0) {
                    container.innerHTML = `
                        <div class="no-messages">
                            <i class="fa-solid fa-box-open"></i>
                            <p style="margin-top: 15px;">No saved messages. Head over to the Encrypt tab to create one!</p>
                        </div>
                    `;
                    return;
                }

                container.innerHTML = '';
                res.messages.forEach(msg => {
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
            } else {
                container.innerHTML = `
                    <div class="no-messages">
                        <i class="fa-solid fa-triangle-exclamation" style="color: var(--color-error)"></i>
                        <p style="margin-top: 15px; color: var(--color-error)">Failed to load messages: ${res.error}</p>
                    </div>
                `;
            }
        } catch (e) {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fa-solid fa-triangle-exclamation" style="color: var(--color-error)"></i>
                    <p style="margin-top: 15px; color: var(--color-error)">Error loading messages: ${e.message}</p>
                </div>
            `;
        }
    }
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

function handleModalDecrypt(event) {
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
    }
}

function handleDeleteMessage(msgId) {
    if (confirm("Are you sure you want to permanently delete this encrypted message from SQLite?")) {
        if (hasAndroidBridge()) {
            try {
                const res = JSON.parse(window.AndroidBridge.deleteMessage(parseInt(msgId)));
                if (res.success) {
                    loadMessages();
                    if (window.AndroidBridge.showToast) {
                        window.AndroidBridge.showToast("Message deleted.");
                    }
                } else {
                    alert("Delete failed: " + res.error);
                }
            } catch (e) {
                alert("Error deleting message: " + e.message);
            }
        }
    }
}

// Hardware Back Button Handler
window.handleAndroidBackPress = function() {
    const modal = document.getElementById('decrypt-modal');
    if (modal && modal.classList.contains('active')) {
        closeDecryptModal();
        return "true";
    }
    return "false";
};

// String escaping utilities
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
