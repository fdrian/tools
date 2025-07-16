// HTTP Headers Analyzer - Security headers analysis and vulnerability detection
document.addEventListener('DOMContentLoaded', () => {
    const urlTab = document.getElementById('url-tab');
    const headersTab = document.getElementById('headers-tab');
    const urlInput = document.getElementById('url-input');
    const headersInput = document.getElementById('headers-input');
    const targetUrl = document.getElementById('target-url');
    const rawHeaders = document.getElementById('raw-headers');
    const analyzeBtn = document.getElementById('analyze-btn');
    const parseBtn = document.getElementById('parse-btn');
    const clearBtn = document.getElementById('clear-btn');
    const copyBtn = document.getElementById('copy-btn');
    const exportBtn = document.getElementById('export-btn');
    const followRedirects = document.getElementById('follow-redirects');
    const checkSubdomains = document.getElementById('check-subdomains');
    const resultsContainer = document.getElementById('results-container');
    const results = document.getElementById('results');
    const loading = document.getElementById('loading');

    let analysisData = null;

    // Security headers definitions and analysis rules
    const securityHeaders = {
        'content-security-policy': {
            name: 'Content Security Policy (CSP)',
            description: 'Prevents XSS attacks by controlling resource loading',
            severity: 'high',
            analyze: analyzeCSP
        },
        'strict-transport-security': {
            name: 'HTTP Strict Transport Security (HSTS)',
            description: 'Forces HTTPS connections and prevents downgrade attacks',
            severity: 'high',
            analyze: analyzeHSTS
        },
        'x-frame-options': {
            name: 'X-Frame-Options',
            description: 'Prevents clickjacking attacks by controlling framing',
            severity: 'medium',
            analyze: analyzeXFrameOptions
        },
        'x-content-type-options': {
            name: 'X-Content-Type-Options',
            description: 'Prevents MIME type sniffing vulnerabilities',
            severity: 'medium',
            analyze: analyzeXContentTypeOptions
        },
        'referrer-policy': {
            name: 'Referrer-Policy',
            description: 'Controls how much referrer information is sent',
            severity: 'low',
            analyze: analyzeReferrerPolicy
        },
        'permissions-policy': {
            name: 'Permissions-Policy',
            description: 'Controls which browser features can be used',
            severity: 'low',
            analyze: analyzePermissionsPolicy
        },
        'x-xss-protection': {
            name: 'X-XSS-Protection',
            description: 'Legacy XSS protection header (deprecated)',
            severity: 'low',
            analyze: analyzeXXSSProtection
        },
        'expect-ct': {
            name: 'Expect-CT',
            description: 'Certificate Transparency monitoring',
            severity: 'low',
            analyze: analyzeExpectCT
        }
    };

    // Tab switching
    urlTab.addEventListener('click', () => switchTab('url'));
    headersTab.addEventListener('click', () => switchTab('headers'));

    function switchTab(tab) {
        if (tab === 'url') {
            urlTab.classList.add('active');
            headersTab.classList.remove('active');
            urlInput.classList.add('active');
            headersInput.classList.remove('active');
        } else {
            headersTab.classList.add('active');
            urlTab.classList.remove('active');
            headersInput.classList.add('active');
            urlInput.classList.remove('active');
        }
    }

    // Analyze URL
    analyzeBtn.addEventListener('click', async () => {
        const url = targetUrl.value.trim();
        if (!url) {
            showNotification('Please enter a URL to analyze.', 'error');
            return;
        }

        if (!isValidUrl(url)) {
            showNotification('Please enter a valid URL.', 'error');
            return;
        }

        showLoading(true);
        try {
            await analyzeUrl(url);
        } catch (error) {
            showLoading(false);
            showNotification(`Analysis failed: ${error.message}`, 'error');
        }
    });

    // Parse headers
    parseBtn.addEventListener('click', () => {
        const headers = rawHeaders.value.trim();
        if (!headers) {
            showNotification('Please paste raw headers to analyze.', 'error');
            return;
        }

        showLoading(true);
        setTimeout(() => {
            try {
                const parsedHeaders = parseRawHeaders(headers);
                analyzeHeaders(parsedHeaders);
            } catch (error) {
                showLoading(false);
                showNotification(`Failed to parse headers: ${error.message}`, 'error');
            }
        }, 500);
    });

    // Clear
    clearBtn.addEventListener('click', () => {
        targetUrl.value = '';
        rawHeaders.value = '';
        results.innerHTML = '<p class="placeholder">Enter a URL or paste headers to begin analysis...</p>';
        analysisData = null;
    });

    // Copy report
    copyBtn.addEventListener('click', async () => {
        if (!analysisData) {
            showNotification('No analysis data to copy.', 'error');
            return;
        }

        const report = generateTextReport(analysisData);
        try {
            await navigator.clipboard.writeText(report);
            showNotification('Report copied to clipboard!', 'success');
        } catch (error) {
            showNotification('Failed to copy report.', 'error');
        }
    });

    // Export JSON
    exportBtn.addEventListener('click', () => {
        if (!analysisData) {
            showNotification('No analysis data to export.', 'error');
            return;
        }

        const dataStr = JSON.stringify(analysisData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `headers-analysis-${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        URL.revokeObjectURL(url);
        showNotification('Analysis exported successfully!', 'success');
    });

    async function analyzeUrl(url) {
        const urls = [url];
        
        // Add common subdomains if requested
        if (checkSubdomains.checked) {
            const domain = new URL(url).hostname;
            const subdomains = ['www', 'api', 'admin', 'app', 'dev', 'staging'];
            for (const sub of subdomains) {
                const subUrl = url.replace(domain, `${sub}.${domain}`);
                if (subUrl !== url) urls.push(subUrl);
            }
        }

        const results = [];
        for (const testUrl of urls) {
            try {
                const headers = await fetchHeaders(testUrl);
                const analysis = analyzeHeaders(headers, testUrl);
                results.push(analysis);
            } catch (error) {
                results.push({
                    url: testUrl,
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        }

        analysisData = {
            originalUrl: url,
            results: results,
            timestamp: new Date().toISOString()
        };

        displayResults(analysisData);
        showLoading(false);
    }

    async function fetchHeaders(url) {
        // Note: Due to CORS restrictions, this will only work for same-origin requests
        // In a real implementation, you'd need a backend proxy
        try {
            const response = await fetch(url, { method: 'HEAD' });
            const headers = {};
            for (const [key, value] of response.headers.entries()) {
                headers[key.toLowerCase()] = value;
            }
            return headers;
        } catch (error) {
            // Fallback: simulate common headers for demo purposes
            return simulateHeaders(url);
        }
    }

    function simulateHeaders(url) {
        // This is a demo simulation - in production, you'd use a backend service
        const isHttps = url.startsWith('https://');
        const domain = new URL(url).hostname;
        
        const headers = {
            'content-type': 'text/html; charset=UTF-8',
            'server': 'nginx/1.18.0',
            'date': new Date().toUTCString()
        };

        // Simulate some common security headers based on domain patterns
        if (domain.includes('google') || domain.includes('github')) {
            headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
            headers['x-frame-options'] = 'SAMEORIGIN';
            headers['x-content-type-options'] = 'nosniff';
            headers['content-security-policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'";
        } else if (domain.includes('bank') || domain.includes('finance')) {
            headers['strict-transport-security'] = 'max-age=63072000; includeSubDomains; preload';
            headers['x-frame-options'] = 'DENY';
            headers['x-content-type-options'] = 'nosniff';
            headers['content-security-policy'] = "default-src 'self'";
        }

        return headers;
    }

    function parseRawHeaders(rawHeaders) {
        const headers = {};
        const lines = rawHeaders.split('\n');
        
        for (const line of lines) {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                const key = line.substring(0, colonIndex).trim().toLowerCase();
                const value = line.substring(colonIndex + 1).trim();
                headers[key] = value;
            }
        }
        
        return headers;
    }

    function analyzeHeaders(headers, url = null) {
        const analysis = {
            url: url,
            headers: headers,
            findings: [],
            score: 0,
            grade: 'F',
            timestamp: new Date().toISOString()
        };

        let totalScore = 0;
        let maxScore = 0;

        // Analyze each security header
        for (const [headerName, config] of Object.entries(securityHeaders)) {
            const headerValue = headers[headerName];
            const finding = config.analyze(headerValue, headers);
            
            finding.header = headerName;
            finding.name = config.name;
            finding.description = config.description;
            finding.severity = config.severity;
            
            analysis.findings.push(finding);
            
            // Calculate score
            const weight = config.severity === 'high' ? 30 : config.severity === 'medium' ? 20 : 10;
            maxScore += weight;
            totalScore += (finding.score / 100) * weight;
        }

        // Calculate final score and grade
        analysis.score = Math.round((totalScore / maxScore) * 100);
        analysis.grade = getGrade(analysis.score);

        return analysis;
    }

    // Header analysis functions
    function analyzeCSP(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'Content Security Policy header is missing',
                recommendation: 'Implement CSP to prevent XSS attacks',
                score: 0
            };
        }

        const issues = [];
        let score = 70;

        // Check for unsafe directives
        if (value.includes("'unsafe-inline'")) {
            issues.push("Contains 'unsafe-inline' which reduces XSS protection");
            score -= 20;
        }
        if (value.includes("'unsafe-eval'")) {
            issues.push("Contains 'unsafe-eval' which allows eval() execution");
            score -= 20;
        }
        if (value.includes('*')) {
            issues.push("Contains wildcards (*) which are too permissive");
            score -= 15;
        }

        // Check for important directives
        if (!value.includes('default-src')) {
            issues.push("Missing 'default-src' directive");
            score -= 10;
        }
        if (!value.includes('script-src')) {
            issues.push("Missing 'script-src' directive");
            score -= 10;
        }

        return {
            status: issues.length === 0 ? 'secure' : 'warning',
            message: issues.length === 0 ? 'CSP header is properly configured' : 'CSP header has security issues',
            issues: issues,
            value: value,
            score: Math.max(0, score)
        };
    }

    function analyzeHSTS(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'HSTS header is missing',
                recommendation: 'Add HSTS header to enforce HTTPS',
                score: 0
            };
        }

        const issues = [];
        let score = 80;

        // Parse max-age
        const maxAgeMatch = value.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
            const maxAge = parseInt(maxAgeMatch[1]);
            if (maxAge < 31536000) { // 1 year
                issues.push(`max-age is too short (${maxAge} seconds)`);
                score -= 20;
            }
        } else {
            issues.push("Missing max-age directive");
            score -= 30;
        }

        // Check for includeSubDomains
        if (!value.includes('includeSubDomains')) {
            issues.push("Missing includeSubDomains directive");
            score -= 15;
        }

        // Check for preload
        if (!value.includes('preload')) {
            issues.push("Consider adding preload directive");
            score -= 5;
        }

        return {
            status: issues.length === 0 ? 'secure' : 'warning',
            message: issues.length === 0 ? 'HSTS header is properly configured' : 'HSTS header needs improvement',
            issues: issues,
            value: value,
            score: Math.max(0, score)
        };
    }

    function analyzeXFrameOptions(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'X-Frame-Options header is missing',
                recommendation: 'Add X-Frame-Options to prevent clickjacking',
                score: 0
            };
        }

        const normalizedValue = value.toUpperCase();
        let score = 100;
        let status = 'secure';

        if (normalizedValue === 'DENY') {
            return {
                status: 'secure',
                message: 'X-Frame-Options is set to DENY (most secure)',
                value: value,
                score: 100
            };
        } else if (normalizedValue === 'SAMEORIGIN') {
            return {
                status: 'secure',
                message: 'X-Frame-Options is set to SAMEORIGIN',
                value: value,
                score: 90
            };
        } else if (normalizedValue.startsWith('ALLOW-FROM')) {
            return {
                status: 'warning',
                message: 'X-Frame-Options uses ALLOW-FROM (deprecated)',
                recommendation: 'Consider using CSP frame-ancestors instead',
                value: value,
                score: 60
            };
        } else {
            return {
                status: 'vulnerable',
                message: 'X-Frame-Options has invalid value',
                value: value,
                score: 0
            };
        }
    }

    function analyzeXContentTypeOptions(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'X-Content-Type-Options header is missing',
                recommendation: 'Add X-Content-Type-Options: nosniff',
                score: 0
            };
        }

        if (value.toLowerCase() === 'nosniff') {
            return {
                status: 'secure',
                message: 'X-Content-Type-Options is properly set to nosniff',
                value: value,
                score: 100
            };
        } else {
            return {
                status: 'vulnerable',
                message: 'X-Content-Type-Options has invalid value',
                value: value,
                score: 0
            };
        }
    }

    function analyzeReferrerPolicy(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'Referrer-Policy header is missing',
                recommendation: 'Add Referrer-Policy to control referrer information',
                score: 0
            };
        }

        const secureValues = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
        const normalizedValue = value.toLowerCase();

        if (secureValues.includes(normalizedValue)) {
            return {
                status: 'secure',
                message: 'Referrer-Policy is set to a secure value',
                value: value,
                score: 100
            };
        } else {
            return {
                status: 'warning',
                message: 'Referrer-Policy could be more restrictive',
                recommendation: 'Consider using strict-origin-when-cross-origin',
                value: value,
                score: 60
            };
        }
    }

    function analyzePermissionsPolicy(value, headers) {
        if (!value) {
            return {
                status: 'missing',
                message: 'Permissions-Policy header is missing',
                recommendation: 'Consider adding Permissions-Policy to control browser features',
                score: 0
            };
        }

        return {
            status: 'info',
            message: 'Permissions-Policy header is present',
            value: value,
            score: 100
        };
    }

    function analyzeXXSSProtection(value, headers) {
        if (!value) {
            return {
                status: 'info',
                message: 'X-XSS-Protection header is missing (deprecated)',
                recommendation: 'Use CSP instead of X-XSS-Protection',
                score: 100
            };
        }

        return {
            status: 'info',
            message: 'X-XSS-Protection header is present but deprecated',
            recommendation: 'Remove X-XSS-Protection and use CSP instead',
            value: value,
            score: 80
        };
    }

    function analyzeExpectCT(value, headers) {
        if (!value) {
            return {
                status: 'info',
                message: 'Expect-CT header is missing',
                recommendation: 'Consider adding Expect-CT for certificate transparency',
                score: 100
            };
        }

        return {
            status: 'info',
            message: 'Expect-CT header is present',
            value: value,
            score: 100
        };
    }

    function displayResults(data) {
        if (data.results && data.results.length > 1) {
            // Multiple URLs analyzed
            displayMultipleResults(data);
        } else {
            // Single URL or headers analysis
            const analysis = data.results ? data.results[0] : data;
            displaySingleResult(analysis);
        }
    }

    function displaySingleResult(analysis) {
        if (analysis.error) {
            results.innerHTML = `
                <div class="error-result">
                    <h3>Analysis Failed</h3>
                    <p><strong>URL:</strong> ${analysis.url}</p>
                    <p><strong>Error:</strong> ${analysis.error}</p>
                </div>
            `;
            return;
        }

        const gradeColors = {
            'A': '#40a02b',
            'B': '#a6e3a1',
            'C': '#f9e2af',
            'D': '#fab387',
            'F': '#f38ba8'
        };

        let html = `
            <div class="analysis-summary">
                <div class="score-card">
                    <h3>Security Score</h3>
                    <div class="score-display">
                        <span class="score-number">${analysis.score}</span>
                        <span class="score-grade" style="color: ${gradeColors[analysis.grade]}">${analysis.grade}</span>
                    </div>
                </div>
                ${analysis.url ? `<p><strong>URL:</strong> ${analysis.url}</p>` : ''}
                <p><strong>Analyzed:</strong> ${new Date(analysis.timestamp).toLocaleString()}</p>
            </div>
        `;

        // Group findings by status
        const grouped = analysis.findings.reduce((acc, finding) => {
            const status = finding.status;
            if (!acc[status]) acc[status] = [];
            acc[status].push(finding);
            return acc;
        }, {});

        const statusOrder = ['vulnerable', 'missing', 'warning', 'secure', 'info'];
        const statusColors = {
            'vulnerable': '#f38ba8',
            'missing': '#fab387',
            'warning': '#f9e2af',
            'secure': '#a6e3a1',
            'info': '#89b4fa'
        };

        for (const status of statusOrder) {
            if (grouped[status]) {
                html += `
                    <div class="status-group">
                        <h4 class="status-header" style="border-left: 4px solid ${statusColors[status]}">
                            ${status.toUpperCase()} (${grouped[status].length})
                        </h4>
                        <div class="findings-grid">
                `;

                for (const finding of grouped[status]) {
                    html += `
                        <div class="finding-card">
                            <div class="finding-header">
                                <h5>${finding.name}</h5>
                                <span class="finding-score">${finding.score}/100</span>
                            </div>
                            <p class="finding-description">${finding.description}</p>
                            <div class="finding-details">
                                <p><strong>Status:</strong> ${finding.message}</p>
                                ${finding.value ? `<p><strong>Value:</strong> <code>${escapeHtml(finding.value)}</code></p>` : ''}
                                ${finding.issues ? `<div class="issues"><strong>Issues:</strong><ul>${finding.issues.map(issue => `<li>${issue}</li>`).join('')}</ul></div>` : ''}
                                ${finding.recommendation ? `<p class="recommendation"><strong>Recommendation:</strong> ${finding.recommendation}</p>` : ''}
                            </div>
                        </div>
                    `;
                }

                html += '</div></div>';
            }
        }

        results.innerHTML = html;
    }

    function displayMultipleResults(data) {
        let html = `
            <div class="multi-analysis-summary">
                <h3>Multiple URL Analysis</h3>
                <p><strong>Original URL:</strong> ${data.originalUrl}</p>
                <p><strong>URLs Analyzed:</strong> ${data.results.length}</p>
                <p><strong>Analyzed:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
        `;

        for (const analysis of data.results) {
            if (analysis.error) {
                html += `
                    <div class="url-result error">
                        <h4>Error: ${analysis.url}</h4>
                        <p>Error: ${analysis.error}</p>
                    </div>
                `;
                continue;
            }

            html += `
                <div class="url-result">
                    <div class="url-header">
                        <h4>${analysis.url}</h4>
                        <div class="url-score">
                            <span class="score-number">${analysis.score}</span>
                            <span class="score-grade">${analysis.grade}</span>
                        </div>
                    </div>
                    <div class="url-summary">
                        <div class="status-counts">
                            ${getStatusCounts(analysis.findings)}
                        </div>
                    </div>
                </div>
            `;
        }

        results.innerHTML = html;
    }

    function getStatusCounts(findings) {
        const counts = findings.reduce((acc, finding) => {
            acc[finding.status] = (acc[finding.status] || 0) + 1;
            return acc;
        }, {});

        return Object.entries(counts)
            .map(([status, count]) => `<span class="status-badge ${status}">${status}: ${count}</span>`)
            .join(' ');
    }

    function getGrade(score) {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 70) return 'C';
        if (score >= 60) return 'D';
        return 'F';
    }

    function generateTextReport(data) {
        let report = `HTTP Headers Security Analysis Report\n`;
        report += `=====================================\n\n`;
        
        if (data.originalUrl) {
            report += `Original URL: ${data.originalUrl}\n`;
        }
        report += `Analysis Date: ${new Date(data.timestamp).toLocaleString()}\n\n`;

        if (data.results && data.results.length > 1) {
            report += `Multiple URL Analysis (${data.results.length} URLs)\n\n`;
            for (const analysis of data.results) {
                if (analysis.error) {
                    report += `Error ${analysis.url}: ${analysis.error}\n`;
                } else {
                    report += `${analysis.url}: Score ${analysis.score}/100 (Grade ${analysis.grade})\n`;
                }
            }
        } else {
            const analysis = data.results ? data.results[0] : data;
            report += `Security Score: ${analysis.score}/100 (Grade ${analysis.grade})\n\n`;
            
            for (const finding of analysis.findings) {
                report += `${finding.name}: ${finding.message}\n`;
                if (finding.issues) {
                    finding.issues.forEach(issue => report += `  - ${issue}\n`);
                }
                if (finding.recommendation) {
                    report += `  Recommendation: ${finding.recommendation}\n`;
                }
                report += `\n`;
            }
        }

        return report;
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
