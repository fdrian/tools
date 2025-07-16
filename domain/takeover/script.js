// Subdomain Takeover Checker - Detect vulnerable subdomains for takeover attacks
document.addEventListener('DOMContentLoaded', () => {
    const singleTab = document.getElementById('single-tab');
    const bulkTab = document.getElementById('bulk-tab');
    const singleInput = document.getElementById('single-input');
    const bulkInput = document.getElementById('bulk-input');
    const singleDomain = document.getElementById('single-domain');
    const bulkDomains = document.getElementById('bulk-domains');
    const checkBtn = document.getElementById('check-btn');
    const bulkCheckBtn = document.getElementById('bulk-check-btn');
    const clearBtn = document.getElementById('clear-btn');
    const copyBtn = document.getElementById('copy-btn');
    const exportBtn = document.getElementById('export-btn');
    const autoDiscover = document.getElementById('auto-discover');
    const checkCname = document.getElementById('check-cname');
    const deepScan = document.getElementById('deep-scan');
    const resultsContainer = document.getElementById('results-container');
    const results = document.getElementById('results');
    const loading = document.getElementById('loading');

    let analysisData = null;

    // Takeover fingerprints for different services
    const takeoverFingerprints = {
        'github': {
            name: 'GitHub Pages',
            patterns: ['github.io', 'github.com'],
            errors: ['There isn\'t a GitHub Pages site here.', 'For root URLs (like http://example.com/) you must provide an index.html file'],
            cname: ['.github.io', '.github.com'],
            vulnerability: 'high'
        },
        'heroku': {
            name: 'Heroku',
            patterns: ['herokuapp.com', 'herokussl.com'],
            errors: ['No such app', 'There\'s nothing here, yet.', 'herokucdn.com/error-pages/no-such-app.html'],
            cname: ['.herokuapp.com', '.herokussl.com'],
            vulnerability: 'high'
        },
        'netlify': {
            name: 'Netlify',
            patterns: ['netlify.app', 'netlify.com'],
            errors: ['Not Found', 'Page Not Found', 'netlify'],
            cname: ['.netlify.app', '.netlify.com'],
            vulnerability: 'medium'
        },
        'vercel': {
            name: 'Vercel',
            patterns: ['vercel.app', 'now.sh'],
            errors: ['The deployment could not be found on Vercel', 'This deployment does not exist'],
            cname: ['.vercel.app', '.now.sh'],
            vulnerability: 'medium'
        },
        'aws-s3': {
            name: 'AWS S3',
            patterns: ['s3.amazonaws.com', 's3-website', 's3.'],
            errors: ['NoSuchBucket', 'The specified bucket does not exist'],
            cname: ['.s3.amazonaws.com', '.s3-website'],
            vulnerability: 'high'
        },
        'azure': {
            name: 'Microsoft Azure',
            patterns: ['azurewebsites.net', 'cloudapp.net', 'trafficmanager.net'],
            errors: ['404 Web Site not found', 'This site has not been deployed yet'],
            cname: ['.azurewebsites.net', '.cloudapp.net', '.trafficmanager.net'],
            vulnerability: 'high'
        },
        'shopify': {
            name: 'Shopify',
            patterns: ['myshopify.com'],
            errors: ['Only one step left!', 'This shop is currently unavailable'],
            cname: ['.myshopify.com'],
            vulnerability: 'high'
        },
        'wordpress': {
            name: 'WordPress.com',
            patterns: ['wordpress.com'],
            errors: ['Do you want to register'],
            cname: ['.wordpress.com'],
            vulnerability: 'medium'
        },
        'tumblr': {
            name: 'Tumblr',
            patterns: ['tumblr.com'],
            errors: ['Whatever you were looking for doesn\'t currently exist at this address'],
            cname: ['.tumblr.com'],
            vulnerability: 'medium'
        },
        'fastly': {
            name: 'Fastly',
            patterns: ['fastly.com'],
            errors: ['Fastly error: unknown domain'],
            cname: ['.fastly.com'],
            vulnerability: 'high'
        },
        'pantheon': {
            name: 'Pantheon',
            patterns: ['pantheonsite.io'],
            errors: ['The gods are wise', '404 error unknown site!'],
            cname: ['.pantheonsite.io'],
            vulnerability: 'high'
        },
        'surge': {
            name: 'Surge.sh',
            patterns: ['surge.sh'],
            errors: ['project not found'],
            cname: ['.surge.sh'],
            vulnerability: 'high'
        },
        'bitbucket': {
            name: 'Bitbucket',
            patterns: ['bitbucket.io'],
            errors: ['Repository not found'],
            cname: ['.bitbucket.io'],
            vulnerability: 'high'
        },
        'webflow': {
            name: 'Webflow',
            patterns: ['webflow.io'],
            errors: ['The page you are looking for doesn\'t exist or has been moved'],
            cname: ['.webflow.io'],
            vulnerability: 'medium'
        },
        'cargo': {
            name: 'Cargo',
            patterns: ['cargocollective.com'],
            errors: ['404 Not Found'],
            cname: ['.cargocollective.com'],
            vulnerability: 'medium'
        },
        'statuspage': {
            name: 'StatusPage',
            patterns: ['statuspage.io'],
            errors: ['You are being redirected'],
            cname: ['.statuspage.io'],
            vulnerability: 'medium'
        }
    };

    // Common subdomains to check
    const commonSubdomains = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'admin',
        'api', 'app', 'dev', 'staging', 'test', 'demo', 'beta', 'alpha', 'preview', 'docs', 'support',
        'help', 'status', 'monitor', 'dashboard', 'panel', 'control', 'manage', 'portal', 'login', 'auth',
        'cdn', 'assets', 'static', 'media', 'images', 'img', 'files', 'downloads', 'upload', 'storage',
        'shop', 'store', 'cart', 'checkout', 'payment', 'pay', 'billing', 'invoice', 'account', 'profile',
        'mobile', 'm', 'wap', 'touch', 'ios', 'android', 'app', 'application', 'service', 'services'
    ];

    // Tab switching
    singleTab.addEventListener('click', () => switchTab('single'));
    bulkTab.addEventListener('click', () => switchTab('bulk'));

    function switchTab(tab) {
        if (tab === 'single') {
            singleTab.classList.add('active');
            bulkTab.classList.remove('active');
            singleInput.classList.add('active');
            bulkInput.classList.remove('active');
        } else {
            bulkTab.classList.add('active');
            singleTab.classList.remove('active');
            bulkInput.classList.add('active');
            singleInput.classList.remove('active');
        }
    }

    // Single domain check
    checkBtn.addEventListener('click', async () => {
        const domain = singleDomain.value.trim();
        if (!domain) {
            showNotification('Please enter a domain to check.', 'error');
            return;
        }

        if (!isValidDomain(domain)) {
            showNotification('Please enter a valid domain.', 'error');
            return;
        }

        showLoading(true);
        try {
            const domains = autoDiscover.checked ? await discoverSubdomains(domain) : [domain];
            const results = await checkMultipleDomains(domains);
            analysisData = {
                type: 'single',
                originalDomain: domain,
                results: results,
                timestamp: new Date().toISOString()
            };
            displayResults(analysisData);
        } catch (error) {
            showNotification(`Check failed: ${error.message}`, 'error');
        } finally {
            showLoading(false);
        }
    });

    // Bulk domain check
    bulkCheckBtn.addEventListener('click', async () => {
        const domainsText = bulkDomains.value.trim();
        if (!domainsText) {
            showNotification('Please enter domains to check.', 'error');
            return;
        }

        const domains = domainsText.split('\n').map(d => d.trim()).filter(d => d);
        if (domains.length === 0) {
            showNotification('Please enter valid domains.', 'error');
            return;
        }

        showLoading(true);
        try {
            const results = await checkMultipleDomains(domains);
            analysisData = {
                type: 'bulk',
                results: results,
                timestamp: new Date().toISOString()
            };
            displayResults(analysisData);
        } catch (error) {
            showNotification(`Bulk check failed: ${error.message}`, 'error');
        } finally {
            showLoading(false);
        }
    });

    // Clear
    clearBtn.addEventListener('click', () => {
        singleDomain.value = '';
        bulkDomains.value = '';
        results.innerHTML = '<p class="placeholder">Enter domains to check for takeover vulnerabilities...</p>';
        analysisData = null;
    });

    // Copy results
    copyBtn.addEventListener('click', async () => {
        if (!analysisData) {
            showNotification('No results to copy.', 'error');
            return;
        }

        const report = generateTextReport(analysisData);
        try {
            await navigator.clipboard.writeText(report);
            showNotification('Results copied to clipboard!', 'success');
        } catch (error) {
            showNotification('Failed to copy results.', 'error');
        }
    });

    // Export CSV
    exportBtn.addEventListener('click', () => {
        if (!analysisData) {
            showNotification('No results to export.', 'error');
            return;
        }

        const csv = generateCSV(analysisData);
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `subdomain-takeover-${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        URL.revokeObjectURL(url);
        showNotification('Results exported successfully!', 'success');
    });

    async function discoverSubdomains(domain) {
        const subdomains = [domain];
        const rootDomain = domain.replace(/^[^.]+\./, '');
        
        // Add common subdomains
        for (const sub of commonSubdomains) {
            if (sub !== domain.split('.')[0]) {
                subdomains.push(`${sub}.${rootDomain}`);
            }
        }
        
        return subdomains;
    }

    async function checkMultipleDomains(domains) {
        const results = [];
        const maxConcurrent = 5;
        
        for (let i = 0; i < domains.length; i += maxConcurrent) {
            const batch = domains.slice(i, i + maxConcurrent);
            const batchPromises = batch.map(domain => checkSingleDomain(domain));
            const batchResults = await Promise.allSettled(batchPromises);
            
            batchResults.forEach((result, index) => {
                if (result.status === 'fulfilled') {
                    results.push(result.value);
                } else {
                    results.push({
                        domain: batch[index],
                        status: 'error',
                        error: result.reason.message,
                        timestamp: new Date().toISOString()
                    });
                }
            });
            
            // Small delay to avoid overwhelming servers
            if (i + maxConcurrent < domains.length) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        
        return results;
    }

    async function checkSingleDomain(domain) {
        const result = {
            domain: domain,
            status: 'safe',
            vulnerability: 'none',
            service: null,
            evidence: [],
            recommendations: [],
            timestamp: new Date().toISOString()
        };

        try {
            // Check if domain resolves and get response
            const response = await fetchWithTimeout(`https://${domain}`, 5000);
            const content = await response.text();
            const responseUrl = response.url;

            // Check for takeover patterns
            for (const [serviceKey, fingerprint] of Object.entries(takeoverFingerprints)) {
                if (checkTakeoverPattern(content, responseUrl, fingerprint)) {
                    result.status = 'vulnerable';
                    result.vulnerability = fingerprint.vulnerability;
                    result.service = fingerprint.name;
                    result.evidence.push(`Domain points to ${fingerprint.name}`);
                    result.recommendations.push(`Verify if ${fingerprint.name} resource is properly configured`);
                    break;
                }
            }

            // Check CNAME records if enabled
            if (checkCname.checked) {
                const cnameResult = await checkCNAMERecord(domain);
                if (cnameResult.vulnerable) {
                    result.status = 'vulnerable';
                    result.vulnerability = cnameResult.vulnerability;
                    result.service = cnameResult.service;
                    result.evidence.push(`CNAME points to unclaimed service: ${cnameResult.target}`);
                    result.recommendations.push(`Check if ${cnameResult.target} is properly configured`);
                }
            }

            // Additional checks for deep scan
            if (deepScan.checked) {
                const deepResult = await performDeepScan(domain, content);
                if (deepResult.vulnerable) {
                    result.status = 'vulnerable';
                    result.vulnerability = deepResult.vulnerability;
                    result.evidence.push(...deepResult.evidence);
                    result.recommendations.push(...deepResult.recommendations);
                }
            }

        } catch (error) {
            if (error.name === 'TimeoutError') {
                result.status = 'timeout';
                result.evidence.push('Request timed out');
            } else if (error.message.includes('ENOTFOUND') || error.message.includes('Name or service not known')) {
                result.status = 'not_found';
                result.evidence.push('Domain does not resolve');
            } else {
                result.status = 'error';
                result.error = error.message;
            }
        }

        return result;
    }

    function checkTakeoverPattern(content, url, fingerprint) {
        // Check URL patterns
        for (const pattern of fingerprint.patterns) {
            if (url.includes(pattern)) {
                // Check for error messages that indicate takeover vulnerability
                for (const errorMsg of fingerprint.errors) {
                    if (content.toLowerCase().includes(errorMsg.toLowerCase())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    async function checkCNAMERecord(domain) {
        // Note: This is a simplified implementation
        // In a real-world scenario, you'd need a backend service to perform DNS lookups
        try {
            const response = await fetch(`https://dns.google/resolve?name=${domain}&type=CNAME`);
            const data = await response.json();
            
            if (data.Answer) {
                for (const record of data.Answer) {
                    if (record.type === 5) { // CNAME record
                        const target = record.data;
                        
                        // Check if CNAME points to vulnerable service
                        for (const [serviceKey, fingerprint] of Object.entries(takeoverFingerprints)) {
                            for (const cnamePattern of fingerprint.cname) {
                                if (target.includes(cnamePattern)) {
                                    return {
                                        vulnerable: true,
                                        service: fingerprint.name,
                                        target: target,
                                        vulnerability: fingerprint.vulnerability
                                    };
                                }
                            }
                        }
                    }
                }
            }
        } catch (error) {
            // Silently fail for CNAME check
        }
        
        return { vulnerable: false };
    }

    async function performDeepScan(domain, content) {
        const evidence = [];
        const recommendations = [];
        let vulnerable = false;
        let vulnerability = 'none';

        // Check for common takeover indicators in content
        const indicators = [
            'github.com/404',
            'heroku | no such app',
            'netlify error',
            'vercel error',
            'aws s3 error',
            'azure error'
        ];

        for (const indicator of indicators) {
            if (content.toLowerCase().includes(indicator)) {
                vulnerable = true;
                vulnerability = 'medium';
                evidence.push(`Found potential takeover indicator: ${indicator}`);
                recommendations.push('Manually verify the service configuration');
                break;
            }
        }

        // Check for specific HTTP status codes that might indicate takeover
        try {
            const response = await fetchWithTimeout(`https://${domain}`, 3000);
            if (response.status === 404) {
                evidence.push('Returns 404 status code');
                recommendations.push('Verify if this is expected behavior');
            }
        } catch (error) {
            // Ignore errors in deep scan
        }

        return {
            vulnerable: vulnerable,
            vulnerability: vulnerability,
            evidence: evidence,
            recommendations: recommendations
        };
    }

    async function fetchWithTimeout(url, timeout) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
            const response = await fetch(url, {
                signal: controller.signal,
                mode: 'no-cors' // This limits what we can do, but avoids CORS issues
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                const timeoutError = new Error('Request timed out');
                timeoutError.name = 'TimeoutError';
                throw timeoutError;
            }
            throw error;
        }
    }

    function displayResults(data) {
        const vulnerableCount = data.results.filter(r => r.status === 'vulnerable').length;
        const totalCount = data.results.length;
        
        let html = `
            <div class="results-summary">
                <h3>Subdomain Takeover Analysis</h3>
                <div class="summary-stats">
                    <div class="stat-item">
                        <span class="stat-number">${totalCount}</span>
                        <span class="stat-label">Domains Checked</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number vulnerable">${vulnerableCount}</span>
                        <span class="stat-label">Vulnerable</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number safe">${totalCount - vulnerableCount}</span>
                        <span class="stat-label">Safe</span>
                    </div>
                </div>
                ${data.originalDomain ? `<p><strong>Original Domain:</strong> ${data.originalDomain}</p>` : ''}
                <p><strong>Analyzed:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
        `;

        // Group results by status
        const grouped = data.results.reduce((acc, result) => {
            if (!acc[result.status]) acc[result.status] = [];
            acc[result.status].push(result);
            return acc;
        }, {});

        const statusOrder = ['vulnerable', 'timeout', 'not_found', 'error', 'safe'];
        const statusLabels = {
            'vulnerable': 'Vulnerable to Takeover',
            'timeout': 'Request Timeout',
            'not_found': 'Domain Not Found',
            'error': 'Check Error',
            'safe': 'Safe'
        };

        for (const status of statusOrder) {
            if (grouped[status] && grouped[status].length > 0) {
                html += `
                    <div class="status-group">
                        <h4 class="status-header ${status}">
                            ${statusLabels[status]} (${grouped[status].length})
                        </h4>
                        <div class="results-grid">
                `;

                for (const result of grouped[status]) {
                    html += createResultCard(result);
                }

                html += '</div></div>';
            }
        }

        results.innerHTML = html;
    }

    function createResultCard(result) {
        const vulnerabilityColors = {
            'high': '#f38ba8',
            'medium': '#fab387',
            'low': '#a6e3a1',
            'none': '#89b4fa'
        };

        let cardHtml = `
            <div class="result-card ${result.status}">
                <div class="result-header">
                    <h5>${result.domain}</h5>
                    ${result.vulnerability !== 'none' ? `<span class="vulnerability-badge ${result.vulnerability}" style="color: ${vulnerabilityColors[result.vulnerability]}">${result.vulnerability.toUpperCase()}</span>` : ''}
                </div>
                <div class="result-details">
                    <p><strong>Status:</strong> ${result.status.replace('_', ' ')}</p>
                    ${result.service ? `<p><strong>Service:</strong> ${result.service}</p>` : ''}
                    ${result.error ? `<p><strong>Error:</strong> ${result.error}</p>` : ''}
        `;

        if (result.evidence && result.evidence.length > 0) {
            cardHtml += `
                <div class="evidence">
                    <strong>Evidence:</strong>
                    <ul>
                        ${result.evidence.map(e => `<li>${e}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (result.recommendations && result.recommendations.length > 0) {
            cardHtml += `
                <div class="recommendations">
                    <strong>Recommendations:</strong>
                    <ul>
                        ${result.recommendations.map(r => `<li>${r}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        cardHtml += `
                    <p class="timestamp">Checked: ${new Date(result.timestamp).toLocaleString()}</p>
                </div>
            </div>
        `;

        return cardHtml;
    }

    function generateTextReport(data) {
        let report = `Subdomain Takeover Analysis Report\n`;
        report += `====================================\n\n`;
        
        const vulnerableCount = data.results.filter(r => r.status === 'vulnerable').length;
        report += `Total Domains Checked: ${data.results.length}\n`;
        report += `Vulnerable Domains: ${vulnerableCount}\n`;
        report += `Analysis Date: ${new Date(data.timestamp).toLocaleString()}\n\n`;

        if (data.originalDomain) {
            report += `Original Domain: ${data.originalDomain}\n\n`;
        }

        for (const result of data.results) {
            report += `Domain: ${result.domain}\n`;
            report += `Status: ${result.status}\n`;
            if (result.service) report += `Service: ${result.service}\n`;
            if (result.vulnerability !== 'none') report += `Vulnerability: ${result.vulnerability}\n`;
            if (result.evidence && result.evidence.length > 0) {
                report += `Evidence: ${result.evidence.join(', ')}\n`;
            }
            if (result.error) report += `Error: ${result.error}\n`;
            report += `\n`;
        }

        return report;
    }

    function generateCSV(data) {
        let csv = 'Domain,Status,Service,Vulnerability,Evidence,Error,Timestamp\n';
        
        for (const result of data.results) {
            const evidence = result.evidence ? result.evidence.join('; ') : '';
            const error = result.error || '';
            csv += `"${result.domain}","${result.status}","${result.service || ''}","${result.vulnerability}","${evidence}","${error}","${result.timestamp}"\n`;
        }
        
        return csv;
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

    function isValidDomain(domain) {
        // Improved regex to handle multiple subdomains and proper hyphen validation
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
        return domainRegex.test(domain);
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
