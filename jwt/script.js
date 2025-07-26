/**
 * JWT Validator Tool
 *
 * This script provides functionality to decode and validate JWT tokens.
 */

// DOM elements
const jwtInput = document.getElementById('jwt-input');
const secretKeySection = document.getElementById('secret-key-section');
const secretKey = document.getElementById('secret-key');
const decodeBtn = document.getElementById('decode-btn');
const validateBtn = document.getElementById('validate-btn');
const clearBtn = document.getElementById('clear-btn');
const headerOutput = document.getElementById('header-output');
const payloadOutput = document.getElementById('payload-output');
const signatureOutput = document.getElementById('signature-output');
const tokenStatus = document.getElementById('token-status');
const tokenExpiry = document.getElementById('token-expiry');
const currentYearElement = document.getElementById('current-year');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');

// JWT Modifier elements
const modifierSecret = document.getElementById('modifier-secret');
const payloadEditor = document.getElementById('payload-editor');
const generateTokenBtn = document.getElementById('generate-token-btn');
const livePreviewCheckbox = document.getElementById('live-preview');
const modifierResult = document.getElementById('modifier-result');

// Set current year in footer
currentYearElement.textContent = new Date().getFullYear();

/**
 * Decodes a JWT token without verifying the signature
 * @param {string} token - JWT token to decode
 * @returns {Object} Object with header, payload, and signature
 */
function decodeJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT token. It must have 3 parts separated by dots.');
        }

        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));

        return {
            header,
            payload,
            signature: parts[2],
            raw: {
                header: parts[0],
                payload: parts[1],
                signature: parts[2]
            }
        };
    } catch (error) {
        showNotification('Failed to decode token: ' + error.message, 'error');
        return null;
    }
}

/**
 * Checks if a JWT token is expired
 * @param {Object} payload - Payload object from the JWT
 * @returns {Object} Expiration status and info
 */
function checkTokenExpiry(payload) {
    if (!payload || !payload.exp) {
        return {
            expired: false,
            message: 'Token has no expiration (exp claim).'
        };
    }

    const expiryDate = new Date(payload.exp * 1000);
    const now = new Date();
    const isExpired = now > expiryDate;

    const diffMs = Math.abs(expiryDate - now);
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

    let timeMessage;
    if (isExpired) {
        timeMessage = `Expired ${diffDays}d ${diffHours}h ${diffMinutes}m ago`;
        if (diffDays === 0) {
            timeMessage = `Expired ${diffHours}h ${diffMinutes}m ago`;
            if (diffHours === 0) {
                timeMessage = `Expired ${diffMinutes} minutes ago`;
            }
        }
    } else {
        timeMessage = `Expires in ${diffDays}d ${diffHours}h ${diffMinutes}m`;
        if (diffDays === 0) {
            timeMessage = `Expires in ${diffHours}h ${diffMinutes}m`;
            if (diffHours === 0) {
                timeMessage = `Expires in ${diffMinutes} minutes`;
            }
        }
    }

    return {
        expired: isExpired,
        expiryDate: expiryDate,
        message: timeMessage
    };
}

/**
 * Formats a JSON object with syntax highlighting
 * @param {Object} obj - JSON object to format
 * @returns {string} HTML with syntax highlighting
 */
function formatJSON(obj) {
    const json = JSON.stringify(obj, null, 2);
    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"([^"]+)":/g, '<span class="key">"$1"</span>:')
        .replace(/"([^"]+)"/g, '<span class="string">"$1"</span>')
        .replace(/\b(true|false)\b/g, '<span class="boolean">$1</span>')
        .replace(/\b(null)\b/g, '<span class="null">$1</span>')
        .replace(/\b(\d+)\b/g, '<span class="number">$1</span>');
}

/**
 * Shows a temporary notification
 * @param {string} message - Message to show
 * @param {string} type - Notification type (success, error, warning, info)
 */
function showNotification(message, type = 'success') {
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('show');
    }, 10);

    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

/**
 * Updates the interface with decoded token information
 * @param {Object} decodedToken - Decoded JWT token
 */
function updateUI(decodedToken) {
    if (!decodedToken) return;

    headerOutput.innerHTML = formatJSON(decodedToken.header);
    payloadOutput.innerHTML = formatJSON(decodedToken.payload);

    // Update payload editor for JWT Modifier
    if (payloadEditor) {
        payloadEditor.value = JSON.stringify(decodedToken.payload, null, 2);
        // Trigger live preview if enabled
        if (livePreviewCheckbox && livePreviewCheckbox.checked) {
            handleLivePreview();
        }
    }

    const alg = decodedToken.header.alg || 'none';
    signatureOutput.innerHTML = `
        <p><strong>Algorithm:</strong> ${alg}</p>
        <p><strong>Signature (encoded):</strong></p>
        <div class="signature-code">${decodedToken.raw.signature}</div>
    `;

    const expiryInfo = checkTokenExpiry(decodedToken.payload);

    if (expiryInfo.expired) {
        tokenStatus.innerHTML = '<span class="expired">Token Expired</span>';
        tokenStatus.className = 'token-status expired';
    } else {
        tokenStatus.innerHTML = '<span>Token Valid (not verified)</span>';
        tokenStatus.className = 'token-status';
    }

    tokenExpiry.textContent = expiryInfo.message;

    if (alg.toLowerCase() !== 'none') {
        secretKeySection.style.display = 'block';
    } else {
        secretKeySection.style.display = 'none';
    }
}

/**
 * Simulates validation of a JWT token
 * NOTE: This is a visual simulation. In real applications, cryptographic validation must be done server-side.
 * @param {string} token - JWT token
 * @param {string} secret - Secret key
 */
async function validateJWT(token, secret) {
    try {
        const decodedToken = decodeJWT(token);
        if (!decodedToken) return;

        const expiryInfo = checkTokenExpiry(decodedToken.payload);

        if (expiryInfo.expired) {
            tokenStatus.innerHTML = '<span class="expired">Token Expired</span>';
            tokenStatus.className = 'token-status expired';
            showNotification('The token has expired!', 'warning');
            return;
        }

        const alg = decodedToken.header.alg;

        if (alg.toUpperCase() !== 'HS256') {
            showNotification(`Unsupported algorithm: ${alg}`, 'error');
            return;
        }

        if (!secret) {
            showNotification('Please provide a secret key to validate the signature', 'error');
            return;
        }

        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            enc.encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const data = `${decodedToken.raw.header}.${decodedToken.raw.payload}`;
        const signatureBuffer = await crypto.subtle.sign(
            'HMAC',
            key,
            enc.encode(data)
        );

        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        if (signatureBase64 === decodedToken.raw.signature) {
            tokenStatus.innerHTML = '<span class="valid">Valid Signature</span>';
            tokenStatus.className = 'token-status valid';
            showNotification('The token signature is valid!', 'success');
        } else {
            tokenStatus.innerHTML = '<span class="invalid">Invalid Signature</span>';
            tokenStatus.className = 'token-status invalid';
            showNotification('The signature does not match the provided key.', 'error');
        }

    } catch (error) {
        showNotification('Error while validating token: ' + error.message, 'error');
    }
}

/**
 * Base64url encode function
 * @param {string} str - String to encode
 * @returns {string} Base64url encoded string
 */
function base64UrlEncode(str) {
    return btoa(str)
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

/**
 * Generate HMAC SHA256 signature
 * @param {string} message - Message to sign
 * @param {string} secret - Secret key
 * @returns {Promise<string>} Base64url encoded signature
 */
async function generateHMACSignature(message, secret) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, data);
    const bytes = new Uint8Array(signature);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return base64UrlEncode(binary);
}

/**
 * Generate a new JWT token with modified payload
 * @param {Object} payload - Modified payload object
 * @param {string} secret - Secret key for signing
 * @returns {Promise<string>} New JWT token
 */
async function generateNewJWT(payload, secret) {
    const header = {
        "alg": "HS256",
        "typ": "JWT"
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const message = encodedHeader + '.' + encodedPayload;
    const signature = await generateHMACSignature(message, secret);

    return message + '.' + signature;
}

/**
 * Display generated token result with live preview styling
 * @param {string} token - Generated JWT token
 * @param {Object} payload - Payload used for generation
 * @param {boolean} isLivePreview - Whether this is a live preview update
 */
function displayTokenResult(token, payload, isLivePreview = false) {
    const title = isLivePreview ? "🔄 Live Preview - Generated Token" : "🚀 Generated Token";
    const resultHTML = `
        <div class="token-result ${isLivePreview ? 'live-preview' : ''}">
            <h5>${title}</h5>
            <div class="payload-info">Payload: ${JSON.stringify(payload)}</div>
            <textarea readonly id="generated-token-output">${token}</textarea>
            ${isLivePreview ? '<div class="live-indicator">Updates automatically as you edit the payload</div>' : ''}
        </div>
    `;
    modifierResult.innerHTML = resultHTML;
}

/**
 * Generate token with live preview support
 * @param {boolean} isLivePreview - Whether this is a live preview update
 */
async function generateToken(isLivePreview = false) {
    const payloadText = payloadEditor.value.trim();
    const secret = modifierSecret.value.trim();

    if (!payloadText) {
        if (!isLivePreview) {
            showNotification('Please decode a token first to populate the payload editor', 'error');
        }
        return;
    }

    if (!secret) {
        if (!isLivePreview) {
            showNotification('Please enter a secret key to sign the token', 'error');
        } else {
            modifierResult.innerHTML = '<div class="token-result"><p>⚠️ Enter a secret key to see the generated token</p></div>';
        }
        return;
    }

    try {
        const payload = JSON.parse(payloadText);
        const newToken = await generateNewJWT(payload, secret);
        displayTokenResult(newToken, payload, isLivePreview);

        if (!isLivePreview) {
            showNotification('Token generated successfully!', 'success');
        }
    } catch (error) {
        if (!isLivePreview) {
            showNotification('Error generating token: ' + error.message, 'error');
        } else {
            modifierResult.innerHTML = `<div class="token-result error"><p>⚠️ Invalid JSON in payload</p></div>`;
        }
    }
}

/**
 * Handle live preview updates with debouncing
 */
let livePreviewTimeout;
function handleLivePreview() {
    if (!livePreviewCheckbox.checked) return;

    clearTimeout(livePreviewTimeout);
    livePreviewTimeout = setTimeout(() => {
        generateToken(true);
    }, 300); // 300ms debounce
}

/**
 * Clear modifier results
 */
function clearModifierResults() {
    if (modifierResult) {
        modifierResult.innerHTML = '';
    }
}

// Event Listeners
decodeBtn.addEventListener('click', () => {
    const token = jwtInput.value.trim();
    if (!token) {
        showNotification('Please enter a JWT token', 'error');
        return;
    }

    const decodedToken = decodeJWT(token);
    if (decodedToken) {
        updateUI(decodedToken);
        showNotification('Token decoded successfully!');
    }
});

validateBtn.addEventListener('click', () => {
    const token = jwtInput.value.trim();
    const key = secretKey.value.trim();

    if (!token) {
        showNotification('Please enter a JWT token', 'error');
        return;
    }

    validateJWT(token, key);
});

clearBtn.addEventListener('click', () => {
    jwtInput.value = '';
    secretKey.value = '';
    headerOutput.textContent = 'Decode a token to view its header';
    payloadOutput.textContent = 'Decode a token to view its payload';
    signatureOutput.innerHTML = '<p>Decode a token to view signature information</p>';
    tokenStatus.textContent = '';
    tokenExpiry.textContent = '';
    secretKeySection.style.display = 'none';

    // Clear JWT Modifier fields
    if (modifierSecret) modifierSecret.value = '';
    if (payloadEditor) payloadEditor.value = '';
    clearModifierResults();

    jwtInput.focus();
    showNotification('Fields cleared');
});

// JWT Modifier Event Listeners
if (generateTokenBtn) {
    generateTokenBtn.addEventListener('click', async () => {
        await generateToken(false);
    });
}

// Live Preview Event Listeners
if (payloadEditor && livePreviewCheckbox) {
    payloadEditor.addEventListener('input', handleLivePreview);
    modifierSecret.addEventListener('input', handleLivePreview);

    livePreviewCheckbox.addEventListener('change', () => {
        if (livePreviewCheckbox.checked) {
            handleLivePreview();
        } else {
            // Clear live preview indicator if disabled
            const existingResult = modifierResult.querySelector('.token-result');
            if (existingResult && existingResult.classList.contains('live-preview')) {
                modifierResult.innerHTML = '';
            }
        }
    });
}

// Tab functionality
tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabPanes.forEach(pane => pane.classList.remove('active'));

        button.classList.add('active');
        const tabId = button.getAttribute('data-tab');
        document.getElementById(`${tabId}-tab`).classList.add('active');
    });
});

// Detect JWT format
jwtInput.addEventListener('input', () => {
    const input = jwtInput.value.trim();
    const parts = input.split('.');
    if (parts.length === 3) {
        decodeBtn.classList.add('highlight');
    } else {
        decodeBtn.classList.remove('highlight');
    }
});

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    jwtInput.focus();

    decodeBtn.classList.add('highlight');

    const exampleToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkcmlhbm8gRnJlaXRhcyIsImZsYWciOiJUaGUgUGF0b255bW91cyBMZWdpb24hIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.lHHqdlnmOTCgSQjorVtZFI-jsuz6CdaYQ0AAJOAxsXY';

    jwtInput.setAttribute('placeholder', `Paste your JWT here (format: xxxxx.yyyyy.zzzzz)\n\nExample: ${exampleToken}`);
    // Secret 🦆🦆🦆🦆🦆🦆🦆🦆🦆🦆
});