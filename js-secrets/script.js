// JavaScript Secrets Finder - Find API keys, tokens and sensitive data
document.addEventListener('DOMContentLoaded', () => {
    const codeTab = document.getElementById('code-tab');
    const urlTab = document.getElementById('url-tab');
    const codeInput = document.getElementById('code-input');
    const urlInput = document.getElementById('url-input');
    const jsCode = document.getElementById('js-code');
    const jsUrl = document.getElementById('js-url');
    const scanBtn = document.getElementById('scan-btn');
    const fetchBtn = document.getElementById('fetch-btn');
    const clearBtn = document.getElementById('clear-btn');
    const copyBtn = document.getElementById('copy-btn');
    const resultsContainer = document.getElementById('results-container');
    const results = document.getElementById('results');
    const loading = document.getElementById('loading');

    // Patterns for different types of secrets
    const secretPatterns = {
        'AWS Access Key': {
            pattern: /AKIA[0-9A-Z]{16}/gi,
            severity: 'high'
        },
        'AWS Secret Key': {
            pattern: /[A-Za-z0-9/+=]{40}/gi,
            severity: 'high',
            context: ['aws', 'secret', 'key']
        },
        'GitHub Token': {
            pattern: /ghp_[A-Za-z0-9]{36}/gi,
            severity: 'high'
        },
        'GitHub Personal Access Token': {
            pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/gi,
            severity: 'high'
        },
        'Stripe API Key': {
            pattern: /sk_live_[A-Za-z0-9]{24}/gi,
            severity: 'high'
        },
        'Stripe Publishable Key': {
            pattern: /pk_live_[A-Za-z0-9]{24}/gi,
            severity: 'medium'
        },
        'Google API Key': {
            pattern: /AIza[0-9A-Za-z\-_]{35}/gi,
            severity: 'high'
        },
        'Firebase Config': {
            pattern: /firebase[A-Za-z]*["\s]*:["\s]*[A-Za-z0-9\-_]+/gi,
            severity: 'medium'
        },
        'JWT Token': {
            pattern: /eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*/gi,
            severity: 'high'
        },
        'Bearer Token': {
            pattern: /Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*/gi,
            severity: 'high'
        },
        'Basic Auth': {
            pattern: /Basic\s+[A-Za-z0-9+\/=]+/gi,
            severity: 'high'
        },
        'API Key Generic': {
            pattern: /["\']?api[_\-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']/gi,
            severity: 'medium'
        },
        'Secret Key Generic': {
            pattern: /["\']?secret[_\-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']/gi,
            severity: 'medium'
        },
        'Access Token': {
            pattern: /["\']?access[_\-]?token["\']?\s*[:=]\s*["\'][A-Za-z0-9\-_]{16,}["\']/gi,
            severity: 'medium'
        },
        'Password': {
            pattern: /["\']?password["\']?\s*[:=]\s*["\'][^"']{8,}["\']/gi,
            severity: 'high'
        },
        'Database URL': {
            pattern: /(mongodb|mysql|postgres|redis):\/\/[^\s"']+/gi,
            severity: 'high'
        },
        'Private Key': {
            pattern: /-----BEGIN[A-Z\s]*PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]*PRIVATE KEY-----/gi,
            severity: 'critical'
        },
        'Slack Token': {
            pattern: /xox[baprs]-[A-Za-z0-9\-]+/gi,
            severity: 'high'
        },
        'Discord Bot Token': {
            pattern: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/gi,
            severity: 'high'
        },
        'Twilio API Key': {
            pattern: /SK[A-Za-z0-9]{32}/gi,
            severity: 'high'
        },
        'SendGrid API Key': {
            pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/gi,
            severity: 'high'
        },
        'Mailgun API Key': {
            pattern: /key-[A-Za-z0-9]{32}/gi,
            severity: 'high'
        },
        'Internal API Endpoint': {
            pattern: /["\']https?:\/\/[a-z0-9\-\.]*\/(api|admin|internal|private)[^\s"']+/gi,
            severity: 'medium'
        },
        'Admin Panel URL': {
            pattern: /["\']https?:\/\/[^\s"']*\/(admin|administrator|dashboard|panel)[^\s"']*/gi,
            severity: 'medium'
        },
        'Email Address': {
            pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
            severity: 'low'
        },
        'IP Address': {
            pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/gi,
            severity: 'low'
        }
    };

    // Tab switching
    codeTab.addEventListener('click', () => {
        switchTab('code');
    });

    urlTab.addEventListener('click', () => {
        switchTab('url');
    });

    function switchTab(tab) {
        if (tab === 'code') {
            codeTab.classList.add('active');
            urlTab.classList.remove('active');
            codeInput.classList.add('active');
            urlInput.classList.remove('active');
        } else {
            urlTab.classList.add('active');
            codeTab.classList.remove('active');
            urlInput.classList.add('active');
            codeInput.classList.remove('active');
        }
    }

    // Scan button
    scanBtn.addEventListener('click', () => {
        const code = jsCode.value.trim();
        if (!code) {
            showNotification('Please paste some JavaScript code to analyze.', 'error');
            return;
        }
        analyzeCode(code);
    });

    // Fetch and scan
    fetchBtn.addEventListener('click', async () => {
        const url = jsUrl.value.trim();
        if (!url) {
            showNotification('Please enter a valid URL.', 'error');
            return;
        }

        if (!isValidUrl(url)) {
            showNotification('Please enter a valid URL.', 'error');
            return;
        }

        showLoading(true);
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const code = await response.text();
            analyzeCode(code, url);
        } catch (error) {
            showLoading(false);
            showNotification(`Failed to fetch URL: ${error.message}`, 'error');
        }
    });

    // Clear button
    clearBtn.addEventListener('click', () => {
        jsCode.value = '';
        jsUrl.value = '';
        results.innerHTML = '<p class="placeholder">Results will appear here after scanning...</p>';
    });

    // Copy results
    copyBtn.addEventListener('click', async () => {
        const resultsText = results.textContent;
        if (!resultsText || resultsText.includes('Results will appear here')) {
            showNotification('No results to copy.', 'error');
            return;
        }

        try {
            await navigator.clipboard.writeText(resultsText);
            showNotification('Results copied to clipboard!', 'success');
        } catch (error) {
            showNotification('Failed to copy results.', 'error');
        }
    });

    function analyzeCode(code, sourceUrl = null) {
        showLoading(true);
        
        // Simulate processing time for better UX
        setTimeout(() => {
            const findings = scanForSecrets(code);
            displayResults(findings, sourceUrl);
            showLoading(false);
        }, 500);
    }

    function scanForSecrets(code) {
        const findings = [];
        const lines = code.split('\n');

        for (const [name, config] of Object.entries(secretPatterns)) {
            const matches = code.match(config.pattern);
            if (matches) {
                const uniqueMatches = [...new Set(matches)];
                
                for (const match of uniqueMatches) {
                    // Find line number
                    let lineNumber = 0;
                    for (let i = 0; i < lines.length; i++) {
                        if (lines[i].includes(match)) {
                            lineNumber = i + 1;
                            break;
                        }
                    }

                    // Check context if required
                    if (config.context) {
                        const contextMatch = config.context.some(ctx => 
                            code.toLowerCase().includes(ctx.toLowerCase())
                        );
                        if (!contextMatch) continue;
                    }

                    findings.push({
                        type: name,
                        value: match,
                        severity: config.severity,
                        lineNumber: lineNumber,
                        context: getContext(lines, lineNumber - 1)
                    });
                }
            }
        }

        return findings;
    }

    function getContext(lines, lineIndex) {
        const start = Math.max(0, lineIndex - 1);
        const end = Math.min(lines.length, lineIndex + 2);
        return lines.slice(start, end).join('\n');
    }

    function displayResults(findings, sourceUrl) {
        if (findings.length === 0) {
            results.innerHTML = `
                <div class="no-results">
                    <h3>✅ No secrets found</h3>
                    <p>No sensitive data patterns were detected in the JavaScript code.</p>
                </div>
            `;
            return;
        }

        // Group by severity
        const grouped = findings.reduce((acc, finding) => {
            if (!acc[finding.severity]) acc[finding.severity] = [];
            acc[finding.severity].push(finding);
            return acc;
        }, {});

        const severityOrder = ['critical', 'high', 'medium', 'low'];
        const severityColors = {
            critical: '#d20f39',
            high: '#fe640b',
            medium: '#df8e1d',
            low: '#1e66f5'
        };

        let html = `
            <div class="results-summary">
                <h3>🔍 Found ${findings.length} potential secret(s)</h3>
                ${sourceUrl ? `<p><strong>Source:</strong> ${sourceUrl}</p>` : ''}
            </div>
        `;

        for (const severity of severityOrder) {
            if (grouped[severity]) {
                html += `
                    <div class="severity-group">
                        <h4 class="severity-header" style="border-left: 4px solid ${severityColors[severity]}">
                            ${severity.toUpperCase()} RISK (${grouped[severity].length})
                        </h4>
                        <div class="findings-list">
                `;

                for (const finding of grouped[severity]) {
                    html += `
                        <div class="finding-item">
                            <div class="finding-header">
                                <span class="finding-type">${finding.type}</span>
                                <span class="finding-line">Line ${finding.lineNumber}</span>
                            </div>
                            <div class="finding-value">
                                <code>${escapeHtml(finding.value)}</code>
                            </div>
                            <div class="finding-context">
                                <details>
                                    <summary>Show context</summary>
                                    <pre><code>${escapeHtml(finding.context)}</code></pre>
                                </details>
                            </div>
                        </div>
                    `;
                }

                html += `
                        </div>
                    </div>
                `;
            }
        }

        results.innerHTML = html;
    }

    function showLoading(show) {
        if (show) {
            loading.classList.remove('hidden');
            results.classList.add('hidden');
        } else {
            loading.classList.add('hidden');
            results.classList.remove('hidden');
        }
    }

    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    // Set current year
    document.getElementById('current-year').textContent = new Date().getFullYear();
});
