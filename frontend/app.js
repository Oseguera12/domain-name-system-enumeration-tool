/* ============================================================
   DNS Enumeration Tool – Frontend Logic
   ============================================================ */

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        document.querySelectorAll('.nav-link').forEach(l => {
            l.classList.remove('active');
            l.removeAttribute('aria-current');
        });
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
        const panelId = 'panel-' + link.dataset.panel;
        document.getElementById(panelId).classList.add('active');
    });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/* @DESCRIPTION: renders a loading spinner with a status message inside a container
 * @PARAMETERS: container [HTMLElement], message [string]
 * @RETURNS: none */
function showLoading(container, message = 'Running enumeration…') {
    container.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <span>${message}</span>
        </div>`;
}

/* @DESCRIPTION: renders an error message inside a container
 * @PARAMETERS: container [HTMLElement], msg [string]
 * @RETURNS: none */
function showError(container, msg) {
    container.innerHTML = `<div class="error-msg">⚠️ ${escapeHtml(msg)}</div>`;
}

/*
 * @DESCRIPTION: escapes a string for safe insertion into HTML
 * @PARAMETERS: str [string]
 * @RETURNS: escaped HTML string [string]
 */
function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

/*
 * @DESCRIPTION: generates an HTML summary stat block with a label and value
 * @PARAMETERS: label [string], value [string|number], cls [string]
 * @RETURNS: HTML string [string]
 */
function summaryItem(label, value, cls = '') {
    return `<div class="summary-item"><div class="label">${label}</div><div class="value ${cls}">${value}</div></div>`;
}

/*
 * @DESCRIPTION: sends a POST request to an API endpoint and returns the parsed JSON response
 * @PARAMETERS: url [string], body [object]
 * @RETURNS: response data [object]
 */
async function apiFetch(url, body) {
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
    return json;
}

// ---------------------------------------------------------------------------
// Load wordlists for dropdowns
// ---------------------------------------------------------------------------

/*
 * @DESCRIPTION: fetches available wordlists from the API and populates dropdowns and the Wordlists panel
 * @PARAMETERS: none
 * @RETURNS: none
 */
async function loadWordlists() {
    try {
        const res = await fetch('/api/wordlists');
        const data = await res.json();
        const options = data.wordlists.map(w =>
            `<option value="${escapeHtml(w.name)}">${escapeHtml(w.name)} (${w.lines >= 0 ? w.lines.toLocaleString() + ' lines' : 'unreadable'})</option>`
        ).join('');
        document.getElementById('sub-wordlist').innerHTML = options || '<option value="subdomain.txt">subdomain.txt</option>';
        document.getElementById('full-wordlist').innerHTML = options || '<option value="subdomain.txt">subdomain.txt</option>';

        // Render the Wordlists panel
        const wlResults = document.getElementById('results-wordlists');
        if (data.wordlists.length === 0) {
            wlResults.innerHTML = '<div class="result-card"><h2>No wordlist files found.</h2><p style="margin-top:8px;color:var(--text-secondary)">Place .txt files in the <code>wordlists/</code> folder.</p></div>';
        } else {
            let html = `<div class="summary-row">${summaryItem('Total Files', data.wordlists.length, 'accent')}${summaryItem('Folder', 'wordlists/', '')}</div>`;
            html += '<div class="result-card"><h2>📂 Wordlist Files</h2>';
            html += '<table class="result-table"><thead><tr><th>Filename</th><th>Lines</th></tr></thead><tbody>';
            for (const w of data.wordlists) {
                const lineStr = w.lines >= 0 ? w.lines.toLocaleString() : '<span style="color:var(--red)">unreadable</span>';
                html += `<tr><td><code>${escapeHtml(w.name)}</code></td><td>${lineStr}</td></tr>`;
            }
            html += '</tbody></table></div>';
            wlResults.innerHTML = html;
        }
    } catch (e) {
        console.warn('Could not load wordlists', e);
        const wlResults = document.getElementById('results-wordlists');
        if (wlResults) wlResults.innerHTML = '<div class="error-msg">⚠️ Could not load wordlists.</div>';
    }
}
loadWordlists();

// Refresh wordlists button
document.getElementById('btn-refresh-wordlists').addEventListener('click', () => {
    const wlResults = document.getElementById('results-wordlists');
    wlResults.innerHTML = '<div class="loading"><div class="spinner"></div><span>Refreshing wordlists…</span></div>';
    loadWordlists();
});

/*
 * @DESCRIPTION: returns the effective wordlist path; custom input overrides the dropdown selection
 * @PARAMETERS: dropdownId [string], customInputId [string]
 * @RETURNS: wordlist path [string]
 */
function getWordlist(dropdownId, customInputId) {
    const custom = document.getElementById(customInputId).value.trim();
    if (custom) return custom;
    return document.getElementById(dropdownId).value;
}

// ---------------------------------------------------------------------------
// 1. DNS Records
// ---------------------------------------------------------------------------

document.getElementById('form-dns-records').addEventListener('submit', async e => {
    e.preventDefault();
    const domain = document.getElementById('dns-domain').value.trim();
    const results = document.getElementById('results-dns-records');
    if (!domain) return;

    showLoading(results, `Querying DNS records for ${domain}…`);

    try {
        const data = await apiFetch('/api/dns-records', { domain });
        let html = '';

        // Summary
        const totalRecords = Object.values(data.records).flat().length;
        const types = Object.keys(data.records).length;
        html += `<div class="summary-row">
            ${summaryItem('Domain', escapeHtml(data.domain), 'accent')}
            ${summaryItem('Record Types', types, 'green')}
            ${summaryItem('Total Records', totalRecords, 'green')}
            ${summaryItem('IPs Found', data.ip_addresses.length, 'accent')}
        </div>`;

        // Records table
        if (totalRecords > 0) {
            html += `<div class="result-card">
                <h2>📋 DNS Records</h2>
                <div class="meta">Timestamp: ${data.timestamp}</div>
                <table class="result-table">
                    <thead><tr><th>Type</th><th>Record Data</th></tr></thead><tbody>`;
            for (const [type, records] of Object.entries(data.records)) {
                for (const r of records) {
                    html += `<tr><td><span class="record-type">${type}</span></td><td>${escapeHtml(r)}</td></tr>`;
                }
            }
            html += `</tbody></table></div>`;
        }

        // Reverse DNS
        if (Object.keys(data.reverse_dns).length > 0) {
            html += `<div class="result-card">
                <h2>🔄 Reverse DNS Lookups</h2>
                <table class="result-table">
                    <thead><tr><th>IP Address</th><th>Hostname(s)</th></tr></thead><tbody>`;
            for (const [ip, hosts] of Object.entries(data.reverse_dns)) {
                html += `<tr><td>${escapeHtml(ip)}</td><td>${hosts.map(escapeHtml).join(', ')}</td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        if (data.errors.length) {
            html += `<div class="result-card"><h2>Errors</h2><ul>${data.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}</ul></div>`;
        }

        results.innerHTML = html || '<div class="result-card"><h2>No records found.</h2></div>';
    } catch (err) {
        showError(results, err.message);
    }
});

// ---------------------------------------------------------------------------
// 2. Subdomains
// ---------------------------------------------------------------------------

document.getElementById('form-subdomains').addEventListener('submit', async e => {
    e.preventDefault();
    const domain = document.getElementById('sub-domain').value.trim();
    const wordlist = getWordlist('sub-wordlist', 'sub-custom-wordlist');
    const showDns = document.getElementById('sub-dns-lookup').checked;
    const threads = parseInt(document.getElementById('sub-threads').value) || 50;
    const timeout = parseInt(document.getElementById('sub-timeout').value) || 5;
    const results = document.getElementById('results-subdomains');
    if (!domain) return;

    showLoading(results, `Enumerating subdomains for ${domain} (${threads} threads, ${timeout}s timeout)… This may take a while.`);

    try {
        const data = await apiFetch('/api/subdomains', { domain, wordlist, show_dns_lookups: showDns, threads, timeout });
        let html = '';

        html += `<div class="summary-row">
            ${summaryItem('Domain', escapeHtml(data.domain), 'accent')}
            ${summaryItem('Checked', data.total_checked.toLocaleString(), '')}
            ${summaryItem('Discovered', data.discovered.length, 'green')}
            ${summaryItem('DNS Only', data.dns_only.length, 'yellow')}
            ${summaryItem('Threads', data.threads, '')}
            ${summaryItem('Timeout', data.timeout + 's', '')}
        </div>`;

        if (data.discovered.length > 0) {
            html += `<div class="result-card">
                <h2>🌐 Discovered Subdomains</h2>
                <div class="meta">Wordlist: ${escapeHtml(data.wordlist)} | Timestamp: ${data.timestamp}</div>
                <table class="result-table">
                    <thead><tr><th>URL</th><th>Status</th></tr></thead><tbody>`;
            for (const s of data.discovered) {
                const badge = s.status === 200 ? 'badge-green' :
                              s.status >= 300 && s.status < 400 ? 'badge-yellow' : 'badge-accent';
                const extra = s.redirect ? ` → ${escapeHtml(s.redirect)}` : '';
                html += `<tr>
                    <td><a href="${escapeHtml(s.url)}" target="_blank" style="color:var(--cyan);text-decoration:none">${escapeHtml(s.url)}</a>${extra}</td>
                    <td><span class="badge ${badge}">${s.status}</span></td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        if (data.dns_only.length > 0) {
            html += `<div class="result-card">
                <h2>🔎 DNS-Only Results</h2>
                <table class="result-table">
                    <thead><tr><th>Domain</th><th>IP</th></tr></thead><tbody>`;
            for (const d of data.dns_only) {
                html += `<tr><td>${escapeHtml(d.domain)}</td><td>${escapeHtml(d.ip)}</td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        if (!data.discovered.length && !data.dns_only.length) {
            html += `<div class="result-card"><h2>No subdomains discovered.</h2></div>`;
        }

        results.innerHTML = html;
    } catch (err) {
        showError(results, err.message);
    }
});

// ---------------------------------------------------------------------------
// 3. Zone Transfer
// ---------------------------------------------------------------------------

document.getElementById('form-zone-transfer').addEventListener('submit', async e => {
    e.preventDefault();
    const domain = document.getElementById('zt-domain').value.trim();
    const results = document.getElementById('results-zone-transfer');
    if (!domain) return;

    showLoading(results, `Testing zone transfer for ${domain}…`);

    try {
        const data = await apiFetch('/api/zone-transfer', { domain });
        let html = '';

        const vuln = data.is_vulnerable;
        html += `<div class="summary-row">
            ${summaryItem('Domain', escapeHtml(data.domain), 'accent')}
            ${summaryItem('Name Servers', data.name_servers.length, '')}
            ${summaryItem('Vulnerable', vuln ? 'YES' : 'NO', vuln ? 'red' : 'green')}
            ${summaryItem('Refused', data.refused.length, 'green')}
        </div>`;

        // Name servers
        html += `<div class="result-card">
            <h2>🖥️ Authoritative Name Servers</h2>
            <table class="result-table"><thead><tr><th>Server</th><th>Status</th></tr></thead><tbody>`;
        for (const ns of data.name_servers) {
            const isVuln = data.vulnerable.some(v => v.server === ns);
            const isRefused = data.refused.includes(ns);
            let badge = '<span class="badge badge-accent">Unknown</span>';
            if (isVuln)    badge = '<span class="badge badge-red">VULNERABLE</span>';
            if (isRefused) badge = '<span class="badge badge-green">Refused (secure)</span>';
            html += `<tr><td>${escapeHtml(ns)}</td><td>${badge}</td></tr>`;
        }
        html += `</tbody></table></div>`;

        // Vulnerable records
        for (const v of data.vulnerable) {
            html += `<div class="result-card">
                <h2>🚨 Zone Transfer Records from ${escapeHtml(v.server)}</h2>
                <div class="meta">${v.total_records} total records (showing up to 100)</div>
                <table class="result-table"><thead><tr><th>Name</th><th>Type</th><th>Data</th></tr></thead><tbody>`;
            for (const r of v.records) {
                html += `<tr><td>${escapeHtml(r.name)}</td><td><span class="record-type">${escapeHtml(r.type)}</span></td><td>${escapeHtml(r.data)}</td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        if (data.errors.length) {
            html += `<div class="result-card"><h2>Errors</h2><ul>${data.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}</ul></div>`;
        }

        results.innerHTML = html;
    } catch (err) {
        showError(results, err.message);
    }
});

// ---------------------------------------------------------------------------
// 4. DNSSEC
// ---------------------------------------------------------------------------

document.getElementById('form-dnssec').addEventListener('submit', async e => {
    e.preventDefault();
    const domain = document.getElementById('dnssec-domain').value.trim();
    const results = document.getElementById('results-dnssec');
    if (!domain) return;

    showLoading(results, `Checking DNSSEC for ${domain}…`);

    try {
        const data = await apiFetch('/api/dnssec', { domain });
        let html = '';

        html += `<div class="summary-row">
            ${summaryItem('Domain', escapeHtml(data.domain), 'accent')}
            ${summaryItem('DNSSEC', data.enabled ? 'ENABLED' : 'DISABLED', data.enabled ? 'green' : 'red')}
            ${summaryItem('DNSKEY Records', data.dnskey_records.length, data.dnskey_records.length ? 'green' : '')}
            ${summaryItem('DS Records', data.ds_records.length, data.ds_records.length ? 'green' : '')}
            ${summaryItem('RRSIG Records', data.rrsig_records.length, data.rrsig_records.length ? 'green' : '')}
        </div>`;

        // Keys
        if (data.keys && data.keys.length) {
            html += `<div class="result-card">
                <h2>🔑 DNSSEC Keys</h2>
                <table class="result-table">
                    <thead><tr><th>Key Type</th><th>Flags</th><th>Protocol</th><th>Algorithm</th></tr></thead><tbody>`;
            for (const k of data.keys) {
                html += `<tr><td>${escapeHtml(k.type)}</td><td>${k.flags}</td><td>${k.protocol}</td><td>${k.algorithm}</td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // DS records
        if (data.ds_records.length) {
            html += `<div class="result-card"><h2>📎 DS Records</h2>
                <table class="result-table"><thead><tr><th>Record</th></tr></thead><tbody>`;
            for (const r of data.ds_records) {
                html += `<tr><td>${escapeHtml(r)}</td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // Validation
        if (data.validation_passed !== undefined) {
            const passed = data.validation_passed;
            html += `<div class="result-card">
                <h2>${passed ? '✅' : '❌'} Validation Test</h2>
                <p style="margin-top:8px;">${passed ? 'DNSSEC validation test passed successfully.' : 'DNSSEC validation test failed.'}</p>
            </div>`;
        }

        // Errors
        if (data.validation_errors.length) {
            html += `<div class="result-card"><h2>⚠️ Issues</h2><ul style="padding-left:20px;margin-top:8px;">
                ${data.validation_errors.map(e => `<li style="margin-bottom:4px;">${escapeHtml(e)}</li>`).join('')}
            </ul></div>`;
        }

        results.innerHTML = html;
    } catch (err) {
        showError(results, err.message);
    }
});

// ---------------------------------------------------------------------------
// 5. Full Enumeration
// ---------------------------------------------------------------------------

document.getElementById('form-full-enum').addEventListener('submit', async e => {
    e.preventDefault();
    const domain = document.getElementById('full-domain').value.trim();
    const wordlist = getWordlist('full-wordlist', 'full-custom-wordlist');
    const showDns = document.getElementById('full-dns-lookup').checked;
    const threads = parseInt(document.getElementById('full-threads').value) || 50;
    const timeout = parseInt(document.getElementById('full-timeout').value) || 5;
    const results = document.getElementById('results-full-enum');
    if (!domain) return;

    results.innerHTML = '';
    let html = '';

    // Progress steps
    const steps = [
        { label: 'DNS Records', pct: 25 },
        { label: 'Subdomains', pct: 50 },
        { label: 'Zone Transfer', pct: 75 },
        { label: 'DNSSEC', pct: 100 },
    ];

    /*
     * @DESCRIPTION: updates the results panel with the current full enumeration progress step
     * @PARAMETERS: step [number]
     * @RETURNS: none
     */
    function showProgress(step) {
        const s = steps[step];
        results.innerHTML = `
            <div class="result-card">
                <h2>⏳ Full Enumeration in Progress</h2>
                <p style="margin:8px 0;">Step ${step + 1}/${steps.length}: ${s.label}</p>
                <div class="progress-bar-container"><div class="progress-bar" style="width:${s.pct}%"></div></div>
            </div>`;
    }

    try {
        // Step 1: DNS Records
        showProgress(0);
        const dnsData = await apiFetch('/api/dns-records', { domain });

        // Step 2: Subdomains
        showProgress(1);
        const subData = await apiFetch('/api/subdomains', { domain, wordlist, show_dns_lookups: showDns, threads, timeout });

        // Step 3: Zone Transfer
        showProgress(2);
        const ztData = await apiFetch('/api/zone-transfer', { domain });

        // Step 4: DNSSEC
        showProgress(3);
        const secData = await apiFetch('/api/dnssec', { domain });

        // Build final report
        const totalRecords = Object.values(dnsData.records).flat().length;
        html += `<div class="summary-row">
            ${summaryItem('Domain', escapeHtml(domain), 'accent')}
            ${summaryItem('DNS Records', totalRecords, 'green')}
            ${summaryItem('Subdomains', subData.discovered.length, 'green')}
            ${summaryItem('Zone Transfer', ztData.is_vulnerable ? 'VULNERABLE' : 'Secure', ztData.is_vulnerable ? 'red' : 'green')}
            ${summaryItem('DNSSEC', secData.enabled ? 'Enabled' : 'Disabled', secData.enabled ? 'green' : 'red')}
        </div>`;

        // DNS Records section
        if (totalRecords > 0) {
            html += `<div class="result-card"><h2>📋 DNS Records</h2>
                <table class="result-table"><thead><tr><th>Type</th><th>Data</th></tr></thead><tbody>`;
            for (const [type, records] of Object.entries(dnsData.records)) {
                for (const r of records) {
                    html += `<tr><td><span class="record-type">${type}</span></td><td>${escapeHtml(r)}</td></tr>`;
                }
            }
            html += `</tbody></table></div>`;
        }

        // Subdomains section
        if (subData.discovered.length) {
            html += `<div class="result-card"><h2>🌐 Discovered Subdomains (${subData.discovered.length})</h2>
                <table class="result-table"><thead><tr><th>URL</th><th>Status</th></tr></thead><tbody>`;
            for (const s of subData.discovered) {
                const badge = s.status === 200 ? 'badge-green' : s.status >= 300 && s.status < 400 ? 'badge-yellow' : 'badge-accent';
                html += `<tr><td><a href="${escapeHtml(s.url)}" target="_blank" style="color:var(--cyan);text-decoration:none">${escapeHtml(s.url)}</a></td>
                    <td><span class="badge ${badge}">${s.status}</span></td></tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // Zone Transfer section
        html += `<div class="result-card"><h2>${ztData.is_vulnerable ? '🚨' : '🛡️'} Zone Transfer</h2>
            <p style="margin-top:8px;">${ztData.is_vulnerable
                ? '<span class="badge badge-red">VULNERABLE</span> Zone transfer vulnerability detected!'
                : '<span class="badge badge-green">SECURE</span> No zone transfer vulnerabilities found.'
            }</p></div>`;

        // DNSSEC section
        html += `<div class="result-card"><h2>${secData.enabled ? '🔒' : '🔓'} DNSSEC Status</h2>
            <p style="margin-top:8px;">${secData.enabled
                ? '<span class="badge badge-green">ENABLED</span> DNSSEC is configured for this domain.'
                : '<span class="badge badge-red">DISABLED</span> DNSSEC is not configured for this domain.'
            }</p></div>`;

        results.innerHTML = html;
    } catch (err) {
        showError(results, err.message);
    }
});
