/**
 * Base64 Encoder/Decoder Tool with Live Mode
 */

const inputText = document.getElementById('input-text');
const outputText = document.getElementById('output-text');
const encodeBtn = document.getElementById('encode-btn');
const decodeBtn = document.getElementById('decode-btn');
const clearBtn = document.getElementById('clear-btn');
const copyBtn = document.getElementById('copy-btn');
const liveToggle = document.getElementById('live-toggle');
const liveModeSelect = document.getElementById('live-mode-select');
const currentYearElement = document.getElementById('current-year');

currentYearElement.textContent = new Date().getFullYear();

function encodeToBase64(str) {
    try {
        return btoa(unescape(encodeURIComponent(str)));
    } catch (error) {
        showNotification('Encoding error: ' + error.message, 'error');
        return '';
    }
}

function decodeFromBase64(str) {
    try {
        return decodeURIComponent(escape(atob(str)));
    } catch (error) {
        showNotification('Decoding error: Invalid Base64 input', 'error');
        return '';
    }
}

function showNotification(message, type = 'success') {
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) existingNotification.remove();

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

encodeBtn.addEventListener('click', () => {
    const input = inputText.value.trim();
    if (!input) return showNotification('Please enter some text to encode', 'error');
    const encoded = encodeToBase64(input);
    outputText.value = encoded;
    if (encoded) showNotification('Text encoded successfully!');
});

decodeBtn.addEventListener('click', () => {
    const input = inputText.value.trim();
    if (!input) return showNotification('Please enter a Base64 string to decode', 'error');
    const decoded = decodeFromBase64(input);
    outputText.value = decoded;
    if (decoded) showNotification('Text decoded successfully!');
});

clearBtn.addEventListener('click', () => {
    inputText.value = '';
    outputText.value = '';
    inputText.focus();
    showNotification('Fields cleared');
});

copyBtn.addEventListener('click', () => {
    if (!outputText.value) return showNotification('Nothing to copy', 'error');
    navigator.clipboard.writeText(outputText.value);
    showNotification('Result copied to clipboard!');
});

inputText.addEventListener('input', () => {
    if (liveToggle.checked) {
        const input = inputText.value;
        const mode = liveModeSelect.value;
        outputText.value = mode === 'encode' ? encodeToBase64(input) : decodeFromBase64(input);
    }

    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    if (inputText.value && base64Regex.test(inputText.value.trim()) && inputText.value.length % 4 === 0) {
        decodeBtn.classList.add('highlight');
        encodeBtn.classList.remove('highlight');
    } else {
        encodeBtn.classList.add('highlight');
        decodeBtn.classList.remove('highlight');
    }
});

liveToggle.addEventListener('change', () => {
    liveModeSelect.disabled = !liveToggle.checked;
    if (liveToggle.checked) {
        const input = inputText.value;
        const mode = liveModeSelect.value;
        outputText.value = mode === 'encode' ? encodeToBase64(input) : decodeFromBase64(input);
    }
});

liveModeSelect.addEventListener('change', () => {
    if (liveToggle.checked) {
        const input = inputText.value;
        const mode = liveModeSelect.value;
        outputText.value = mode === 'encode' ? encodeToBase64(input) : decodeFromBase64(input);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    inputText.focus();
    encodeBtn.classList.add('highlight');
    inputText.setAttribute('title', 'Tip: Ctrl+Enter to encode, Shift+Enter to decode');
});
