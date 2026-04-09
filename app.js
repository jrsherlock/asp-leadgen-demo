/* ============================================
   ASP Lead-Gen Demo — App Logic
   ProCircular Attack Surface Profiler
   Anonymized demo data
   ============================================ */

// ----- Demo Scan Data -----
const DEMO_DATA = {
  organization: { primary_domain: 'acmecorp.com', name: 'Acme Corporation' },
  risk_score: 92,

  summary: {
    total_subdomains: 23190,
    live_subdomains: 147,
    total_ips: 21,
    internet_exposed_services: 260,
    live_web_apps: 148,
    total_findings: 828,
    critical_findings: 7,
    high_findings: 75,
    medium_findings: 38,
    low_findings: 53,
    total_technologies: 112,
    ssl_issues: 6,
    dns_issues: 4,
    credential_exposures: 915,
    breached_emails: 261,
    infostealer_exposures: 645,
    brand_risk_lookalikes: 14,
    waf_protected_assets: 16,
    waf_unprotected_assets: 131,
    waf_protection_percentage: 10.9,
    screenshots_captured: 153,
    favicon_hashes: 29,
    kev_findings: 1,
    high_epss_findings: 5,
    exploitable_findings: 0
  },

  // Stat cards displayed in results header
  statCards: [
    { label: 'Endpoints', value: 148, sub: '7 critical vulns found', icon: 'globe', link: 'endpoints-section', color: '#22c55e' },
    { label: 'Breached Emails', value: 261, sub: '915 credentials exposed', icon: 'shield-alert', link: 'breaches-section', color: '#ef4444' },
    { label: 'Subdomains', value: 23190, sub: '147 live hosts', icon: 'sitemap', link: 'dual-section', color: '#3b82f6' },
    { label: 'Services', value: 260, sub: '21 unique IPs', icon: 'server', link: 'dual-section', color: '#a855f7' },
    { label: 'SSL Certs', value: 27, sub: '6 issues detected', icon: 'lock', link: 'ssl-section', color: '#06b6d4' },
    { label: 'Typosquats', value: 14, sub: '11 high threat', icon: 'alert-triangle', link: 'typosquats-section', color: '#f97316' }
  ],

  // Endpoints — anonymized web apps
  endpoints: [
    { url: 'https://acmecorp.com', title: 'Acme Corporation \u2014 Main Site', vulns: { c: 0, h: 2, m: 3 }, status: 'live', tech: 'nginx, Bootstrap, jQuery 1.11.1' },
    { url: 'https://mail.acmecorp.com', title: 'Microsoft Outlook Web Access 15.2', vulns: { c: 1, h: 3, m: 2 }, status: 'warning', tech: 'IIS 10.0, ASP.NET 4.0, Exchange' },
    { url: 'https://training.acmecorp.com', title: 'Training Portal \u2014 lighttpd / PHP 5.6.40', vulns: { c: 2, h: 4, m: 1 }, status: 'critical', tech: 'lighttpd 1.4.74, PHP 5.6.40' },
    { url: 'https://blog.acmecorp.com', title: 'Company Blog \u2014 WordPress 6.9.4', vulns: { c: 0, h: 1, m: 2 }, status: 'live', tech: 'WordPress 6.9.4, Elementor, PHP' },
    { url: 'https://vault.acmecorp.com', title: 'Vault \u2014 Internal Application', vulns: { c: 0, h: 1, m: 1 }, status: 'live', tech: 'nginx' },
    { url: 'https://portal.acmecorp.com', title: 'Employee Portal \u2014 HR System', vulns: { c: 0, h: 2, m: 1 }, status: 'live', tech: 'nginx' },
    { url: 'https://support.acmecorp.com', title: 'Zendesk Support Portal', vulns: { c: 0, h: 0, m: 1 }, status: 'live', tech: 'Cloudflare, Zendesk' },
    { url: 'https://pages.acmecorp.com', title: 'HubSpot CMS Landing Pages', vulns: { c: 0, h: 1, m: 0 }, status: 'live', tech: 'Cloudflare, HubSpot' },
    { url: 'https://notify.acmecorp.com', title: 'Admin Panel \u2014 PHP 8.1.34', vulns: { c: 0, h: 1, m: 2 }, status: 'warning', tech: 'nginx, PHP 8.1.34' },
    { url: 'https://mailer.acmecorp.com', title: 'Acme Corporation Mailer', vulns: { c: 0, h: 0, m: 1 }, status: 'live', tech: 'nginx, PHP 8.4, Bootstrap, jQuery' }
  ],
  endpoints_total: 148,

  // Breach findings — anonymized credential exposures
  breaches: [
    { email: 'jsmith@acmecorp.com', source: 'Infostealer Malware', dataType: 'Plaintext Password', risk: 'critical', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' },
    { email: 'mwilson@acmecorp.com', source: 'Infostealer Malware', dataType: 'Plaintext Password', risk: 'critical', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' },
    { email: 'kpatel@acmecorp.com', source: 'Infostealer Malware', dataType: 'Browser Cookies + Password', risk: 'critical', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' },
    { email: 'rchen@acmecorp.com', source: 'Credential Dump', dataType: 'Plaintext Password', risk: 'high', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' },
    { email: 'ljohnson@acmecorp.com', source: 'Credential Dump', dataType: 'Plaintext Password', risk: 'high', date: '2026-04-06', breach: '400KMIX.txt' },
    { email: 'kpatel@acmecorp.com', source: 'Credential Dump', dataType: 'Plaintext Password', risk: 'high', date: '2026-04-06', breach: '400KMIX.txt' },
    { email: 'dgarcia@acmecorp.com', source: 'Credential Dump', dataType: 'Plaintext Password', risk: 'high', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' },
    { email: 'tmartin@acmecorp.com', source: 'Credential Dump', dataType: 'Plaintext Password', risk: 'high', date: '2026-04-03', breach: '@Grafiker27 138GB ULP' }
  ],
  breaches_total: 915,

  // Subdomains — anonymized live subdomains
  subdomains: [
    { name: 'acmecorp.com', status: 'live', ip: '198.51.XX.30', sources: 'bbot, httpx, shodan' },
    { name: 'mail.acmecorp.com', status: 'live', ip: '198.51.XX.150', sources: 'bbot, shodan, subfinder' },
    { name: 'webmail.acmecorp.com', status: 'live', ip: '198.51.XX.150', sources: 'bbot, crt.sh, naabu, shodan' },
    { name: 'vault.acmecorp.com', status: 'live', ip: '198.51.XX.57', sources: 'bbot, naabu, shodan' },
    { name: 'portal.acmecorp.com', status: 'live', ip: '198.51.XX.74', sources: 'bbot, naabu, shodan' },
    { name: 'docs.acmecorp.com', status: 'live', ip: '203.0.XX.51', sources: 'bbot, crt.sh, shodan' },
    { name: 'training.acmecorp.com', status: 'live', ip: '203.0.XX.2', sources: 'bbot, shodan' },
    { name: 'staging.acmecorp.com', status: 'live', ip: '203.0.XX.100', sources: 'bbot, crt.sh, shodan' },
    { name: 'support.acmecorp.com', status: 'live', ip: '203.0.XX.6', sources: 'bbot, subfinder' },
    { name: 'pages.acmecorp.com', status: 'live', ip: '203.0.XX.28', sources: 'bbot, shodan, subfinder' }
  ],
  subdomains_total: 23190,

  // Open ports & services — anonymized scan data
  ports: [
    { host: 'mail.acmecorp.com', port: 25, service: 'SMTP', product: 'Microsoft Exchange', status: 'warning', ip: '198.51.XX.150' },
    { host: 'mail.acmecorp.com', port: 443, service: 'HTTPS', product: 'IIS 10.0 / OWA 15.2', status: 'warning', ip: '198.51.XX.150' },
    { host: 'mail.acmecorp.com', port: 587, service: 'SMTP', product: 'Exchange Submission', status: 'warning', ip: '198.51.XX.150' },
    { host: 'vpn1.acmecorp.com', port: 22, service: 'SSH', product: 'OpenSSH', status: 'warning', ip: '198.51.XX.XX' },
    { host: 'vpn1.acmecorp.com', port: 161, service: 'SNMP', product: 'SNMP Agent', status: 'critical', ip: '198.51.XX.XX' },
    { host: 'vpn2.acmecorp.com', port: 500, service: 'IKE', product: 'VPN Gateway', status: 'warning', ip: '198.51.XX.XX' },
    { host: 'legacy.acmecorp.com', port: 211, service: 'TCP/211', product: 'Unknown Service', status: 'critical', ip: '198.51.XX.37' },
    { host: 'ns1.acmecorp.com', port: 53, service: 'DNS', product: 'DNS Server', status: 'warning', ip: '198.51.XX.XX' },
    { host: 'pages.acmecorp.com', port: 8080, service: 'HTTP', product: 'HubSpot Proxy', status: 'live', ip: '203.0.XX.28' },
    { host: 'pages.acmecorp.com', port: 8443, service: 'HTTPS', product: 'HubSpot Proxy', status: 'live', ip: '203.0.XX.28' },
    { host: 'remote.acmecorp.com', port: 1701, service: 'L2TP', product: 'L2TP/VPN Tunnel', status: 'critical', ip: '198.51.XX.100' },
    { host: 'rdpgw.acmecorp.com', port: 443, service: 'HTTPS', product: 'RDP Gateway / IIS 10.0', status: 'critical', ip: '198.51.XX.166' }
  ],
  ports_total: 260,

  // Technologies — real detections from the scan
  technologies: [
    { name: 'nginx', version: '', icon: 'server' },
    { name: 'OpenSSH', version: '9.6p1', icon: 'terminal' },
    { name: 'Microsoft IIS', version: '10.0', icon: 'server' },
    { name: 'Microsoft Exchange', version: '15.2.1748', icon: 'globe' },
    { name: 'ASP.NET', version: '4.0.30319', icon: 'code' },
    { name: 'PHP', version: '5.6.40', icon: 'code' },
    { name: 'PHP', version: '8.3.30', icon: 'code' },
    { name: 'WordPress', version: '6.9.4', icon: 'globe' },
    { name: 'Cloudflare', version: '', icon: 'shield' },
    { name: 'jQuery', version: '1.11.1', icon: 'layers' },
    { name: 'MariaDB', version: '10.11.14', icon: 'server' },
    { name: 'lighttpd', version: '1.4.74', icon: 'server' },
    { name: 'Sendmail', version: '8.15.2', icon: 'globe' },
    { name: 'Cisco IOS', version: '15.5(3)S8', icon: 'settings' },
    { name: 'Postfix', version: '', icon: 'globe' },
    { name: 'Bootstrap', version: '3.3.2', icon: 'layout' }
  ],
  technologies_total: 112,

  // SSL certificates — anonymized posture data
  certificates: [
    { domain: '*.acmecorp.com', expiry: '2027-03-01', status: 'valid', issuer: 'Cloudflare Inc ECC CA-3', issues: 'None' },
    { domain: 'mail.acmecorp.com', expiry: '2026-11-15', status: 'valid', issuer: 'DigiCert SHA2', issues: 'TLSv1.0 + TLSv1.1 enabled' },
    { domain: 'staging.acmecorp.com', expiry: '2026-09-20', status: 'valid', issuer: 'Microsoft Azure RSA', issues: 'TLSv1.0 + TLSv1.1 enabled' },
    { domain: 'training.acmecorp.com', expiry: '2026-05-06', status: 'expiring', issuer: "Let's Encrypt R11", issues: 'Expiring in 28 days' },
    { domain: 'pages.acmecorp.com', expiry: '2026-12-01', status: 'valid', issuer: 'Cloudflare Inc ECC CA-3', issues: 'TLSv1.0 + TLSv1.1 enabled' },
    { domain: 'docs.acmecorp.com', expiry: '2027-01-15', status: 'valid', issuer: 'Amazon RSA 2048', issues: 'None' }
  ],
  certificates_total: 27,

  // Typosquats — anonymized lookalike domains
  typosquats: [
    { domain: 'acmecorp.net', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'Active web + mail server' },
    { domain: 'acmecorp.org', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'Hover Realnames email service' },
    { domain: 'acmecorp.io', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'GitHub Pages blog' },
    { domain: 'acmecorp.info', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: false, note: 'Active web server' },
    { domain: 'acmecorp.co', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'Apache web server' },
    { domain: 'acmecorp.me', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'Mastodon instance' },
    { domain: 'acmecorp.cc', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'Outlook mail protection' },
    { domain: 'acmecorp.us', category: 'TLD Swap', threat: 'high', hasWeb: false, hasMX: true, note: 'Outlook mail protection' },
    { domain: 'acmecorp.app', category: 'TLD Swap', threat: 'high', hasWeb: true, hasMX: true, note: 'LiteSpeed server' },
    { domain: 'acmecorp.xyz', category: 'TLD Swap', threat: 'high', hasWeb: false, hasMX: true, note: 'Outlook mail \u2014 email only' },
    { domain: 'acmecorp.cloud', category: 'TLD Swap', threat: 'medium', hasWeb: true, hasMX: false, note: 'Redirects to acmecorp.com' },
    { domain: 'acmecorp.dev', category: 'TLD Swap', threat: 'medium', hasWeb: true, hasMX: false, note: 'Vercel \u2014 dev portfolio' },
    { domain: 'acme-corp.com', category: 'Typosquat', threat: 'medium', hasWeb: true, hasMX: false, note: 'Active web server' },
    { domain: 'acmecorps.com', category: 'Typosquat', threat: 'medium', hasWeb: true, hasMX: false, note: 'Parked domain' }
  ],
  typosquats_total: 14,

  // Executive narrative highlights (for possible future use)
  highlights: {
    kev_warning: '1 vulnerability listed in CISA Known Exploited Vulnerabilities catalog',
    infostealer_warning: '645 infostealer-sourced credentials from 62 employees',
    waf_gap: '89% of web assets lack WAF protection',
    dangling_cnames: '4 dangling CNAME records \u2014 subdomain takeover risk',
    deprecated_tls: '6 services running deprecated TLSv1.0/1.1'
  },

  // Scan phases — durations randomized at runtime (3-8s each)
  scanPhases: [
    { name: 'Subdomain Discovery', desc: 'Enumerating DNS records, certificate transparency logs, and passive sources' },
    { name: 'Port Scanning', desc: 'Probing 260 services across 21 IP addresses' },
    { name: 'Service Fingerprinting', desc: 'Identifying 112 technologies and software versions' },
    { name: 'SSL/TLS Analysis', desc: 'Auditing 27 certificates and cipher configurations' },
    { name: 'Vulnerability Detection', desc: 'Running 6,900+ Nuclei templates across live hosts' },
    { name: 'Credential Monitoring', desc: 'Searching breach databases for 440 email addresses' },
    { name: 'Brand Risk Analysis', desc: 'Checking domain permutations and lookalike registrations' },
    { name: 'Report Compilation', desc: 'Scoring risk factors and generating intelligence report' }
  ]
};

// ----- SVG Icon Helpers -----
const ICONS = {
  globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  'shield-alert': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
  sitemap: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="6" height="4" rx="1"/><rect x="2" y="18" width="6" height="4" rx="1"/><rect x="16" y="18" width="6" height="4" rx="1"/><path d="M12 6v6"/><path d="M5 18v-3a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v3"/></svg>',
  server: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
  cpu: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>',
  lock: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  'alert-triangle': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  code: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
  shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  settings: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  layers: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
  terminal: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
  layout: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>',
  lockSmall: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  checkCircle: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
};

function icon(name) { return ICONS[name] || ''; }

// ----- State -----
const state = {
  phase: 'hero',
  scanDomain: '',
  phaseIndex: 0
};

// ----- DOM Helpers -----
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

// ----- Init -----
document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = $('#scan-btn');
  const domainInput = $('#domain-input');
  const leadForm = $('#lead-form');

  // Pre-fill with demo domain
  domainInput.value = 'acmecorp.com';

  scanBtn.addEventListener('click', () => {
    const raw = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!raw || !isValidDomain(raw)) {
      $('.scan-input-group').classList.add('shake');
      setTimeout(() => $('.scan-input-group').classList.remove('shake'), 400);
      domainInput.focus();
      return;
    }
    startScan(raw);
  });

  domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') scanBtn.click();
  });

  leadForm.addEventListener('submit', handleLeadCapture);
});

// ----- Per-phase live feed data (real discoveries to stream) -----
const PHASE_FEEDS = {
  0: { // Subdomain Discovery
    items: [
      'acmecorp.com', 'www.acmecorp.com', 'mail.acmecorp.com', 'webmail.acmecorp.com',
      'vault.acmecorp.com', 'portal.acmecorp.com', 'sso.acmecorp.com', 'vpn.acmecorp.com',
      'docs.acmecorp.com', 'blog.acmecorp.com', 'alumni.acmecorp.com',
      'apply.acmecorp.com', 'staging.acmecorp.com', 'dev.acmecorp.com',
      'support.acmecorp.com', 'pages.acmecorp.com', 'training.acmecorp.com',
      'wiki.acmecorp.com', 'go.acmecorp.com', 'cdn.acmecorp.com',
      'api.acmecorp.com', 'vpn1.acmecorp.com', 'vpn2.acmecorp.com',
      'legacy.acmecorp.com', 'remote.acmecorp.com', 'mailer.acmecorp.com',
      'notify.acmecorp.com', 'test.acmecorp.com', 'devops.acmecorp.com',
      'admin.acmecorp.com', 'sandbox.acmecorp.com',
      'ns1.acmecorp.com', 'rdpgw.acmecorp.com',
      'backup.acmecorp.com', 'monitor.acmecorp.com'
    ],
    badge: { text: '23,190 found', cls: 'found' },
    consoleLines: [
      { cmd: 'subfinder', msg: 'Querying 40+ passive sources for acmecorp.com' },
      { cmd: 'bbot', msg: 'Starting recursive enumeration...' },
      { ok: true, msg: 'crt.sh returned 847 certificate entries' },
      { ok: true, msg: 'subfinder found 312 unique subdomains' },
      { ok: true, msg: 'bbot discovered 22,841 DNS records' },
      { info: true, msg: 'Consolidating and deduplicating results...' },
      { ok: true, msg: '23,190 total subdomains identified (147 live)' }
    ]
  },
  1: { // Port Scanning
    items: [
      '143.207.1.30:443 \u2192 HTTPS/nginx', '143.207.1.30:80 \u2192 HTTP/nginx',
      '143.207.2.150:443 \u2192 HTTPS/IIS', '143.207.2.150:25 \u2192 SMTP/Exchange',
      '143.207.2.150:587 \u2192 SMTP', '143.207.2.150:465 \u2192 SMTPS',
      '143.207.2.37:211 \u2192 TCP/unknown', '143.207.2.37:80 \u2192 HTTP/Apache',
      '143.207.2.100:1701 \u2192 L2TP', '143.207.2.166:443 \u2192 RDP Gateway',
      '199.60.103.28:8080 \u2192 HTTP/HubSpot', '199.60.103.28:8443 \u2192 HTTPS',
      '199.60.103.28:2083 \u2192 cPanel', '54.156.168.2:443 \u2192 HTTPS/lighttpd',
      '13.57.92.51:443 \u2192 HTTPS/nginx'
    ],
    badge: { text: '260 services', cls: 'found' },
    consoleLines: [
      { cmd: 'naabu', msg: 'Two-pass scan: top-1000 on 147 live hosts' },
      { info: true, msg: 'Phase 1: Scanning live hosts from httpx results...' },
      { warn: true, msg: 'SNMP (161/tcp) open on vpn1.acmecorp.com' },
      { warn: true, msg: 'RDP Gateway detected on rdpgw.acmecorp.com:443' },
      { crit: true, msg: 'L2TP/VPN tunnel on remote.acmecorp.com:1701' },
      { info: true, msg: 'Phase 2: High-risk probe on remaining hosts...' },
      { ok: true, msg: '260 internet-exposed services across 21 IPs' }
    ]
  },
  2: { // Service Fingerprinting
    items: [
      'nginx \u2014 multiple hosts', 'Microsoft IIS 10.0', 'OpenSSH 9.6p1',
      'Microsoft Exchange 15.2.1748', 'PHP 5.6.40 (EOL!)', 'PHP 8.3.30',
      'WordPress 6.9.4', 'Cloudflare WAF', 'jQuery 1.11.1',
      'MariaDB 10.11.14', 'lighttpd 1.4.74', 'ASP.NET 4.0.30319',
      'Cisco IOS 15.5(3)S8', 'Bootstrap 3.3.2', 'EZproxy', 'Sendmail 8.15.2'
    ],
    badge: { text: '112 technologies', cls: 'found' },
    consoleLines: [
      { cmd: 'httpx', msg: 'Fingerprinting 148 live web applications' },
      { ok: true, msg: 'Detected nginx on 14 hosts' },
      { warn: true, msg: 'PHP 5.6.40 detected \u2014 end-of-life since 2018' },
      { info: true, msg: 'Exchange Server 15.2.1748 on mail.acmecorp.com' },
      { warn: true, msg: 'jQuery 1.11.1 \u2014 known XSS vulnerabilities' },
      { ok: true, msg: '112 unique technology components identified' }
    ]
  },
  3: { // SSL/TLS Analysis
    items: [
      '*.acmecorp.com \u2014 Cloudflare ECC \u2714', 'mail: TLSv1.0+1.1 enabled',
      'staging: TLSv1.0+1.1 enabled', 'pages: TLSv1.0+1.1 enabled',
      'training: expires in 28 days', 'docs \u2014 Amazon RSA \u2714'
    ],
    badge: { text: '6 issues', cls: 'warn' },
    consoleLines: [
      { cmd: 'nuclei', msg: 'SSL/TLS template scan on 27 services' },
      { warn: true, msg: '3 services support deprecated TLSv1.0' },
      { warn: true, msg: '3 services support deprecated TLSv1.1' },
      { warn: true, msg: 'training.acmecorp.com cert expiring in 28 days' },
      { ok: true, msg: '27 certificates audited, 6 issues found' }
    ]
  },
  4: { // Vulnerability Detection
    items: [
      'CVE-2019-9641 \u2014 PHP (learninghub)', 'CVE-2017-8923 \u2014 PHP (learninghub)',
      'CVE-2024-3566 \u2014 PHP (training)', 'OpenID endpoint exposed (acmecorp.com)',
      'OAuth endpoint sprayable', 'CISA KEV: CVE-2024-3566',
      'EPSS >50%: 5 vulnerabilities', '4 dangling CNAMEs \u2014 takeover risk',
      'Exchange OWA exposed', 'Default IIS page on legacy.acmecorp.com'
    ],
    badge: { text: '7 CRITICAL', cls: 'alert' },
    consoleLines: [
      { cmd: 'nuclei', msg: 'Running 6,900+ templates across live hosts (parallel)' },
      { info: true, msg: 'Phase 1a: CVEs + vulnerabilities + exposed panels' },
      { info: true, msg: 'Phase 1b: Exposures + misconfigurations (parallel)' },
      { crit: true, msg: 'CVE-2024-3566 on learninghub \u2014 CISA KEV listed!' },
      { crit: true, msg: '7 critical, 75 high-severity findings' },
      { warn: true, msg: '5 findings with EPSS >50% (exploitation likely)' },
      { warn: true, msg: '4 dangling CNAME records \u2014 subdomain takeover risk' },
      { ok: true, msg: '828 total findings across 6 categories' }
    ]
  },
  5: { // Credential Monitoring
    items: [
      'daniellegra@ \u2014 Infostealer (plaintext)', 'kodjo@ \u2014 Infostealer (plaintext)',
      'abrahamw@ \u2014 Browser cookies + pwd', 'sthillaa@ \u2014 Credential dump',
      'hyungk@ \u2014 Credential dump', 'polk@ \u2014 Credential dump',
      'abelardo@ \u2014 Credential dump', '... scanning 440 email addresses'
    ],
    badge: { text: '915 exposed', cls: 'alert' },
    consoleLines: [
      { cmd: 'hacknotice', msg: 'Querying breach databases for 440 emails' },
      { crit: true, msg: '645 infostealer records from 62 employees!' },
      { crit: true, msg: 'Plaintext passwords found in multiple dumps' },
      { warn: true, msg: 'Source: @Grafiker27 138GB ULP (2026-04-03)' },
      { warn: true, msg: 'Source: 400KMIX.txt (2026-04-06)' },
      { crit: true, msg: '261 unique email addresses compromised' },
      { ok: true, msg: '915 total credential exposure records' }
    ]
  },
  6: { // Brand Risk Analysis
    items: [
      'acmecorp.net \u2014 TLD swap (HIGH)', 'acmecorp.org \u2014 TLD swap (HIGH)',
      'acmecorp.io \u2014 GitHub Pages (HIGH)', 'acmecorp.co \u2014 TLD swap (HIGH)',
      'acmecorp.me \u2014 Mastodon instance', 'acmecorp.cc \u2014 Outlook MX',
      'acmecorp.app \u2014 LiteSpeed', 'acme-corp.com \u2014 Typosquat'
    ],
    badge: { text: '11 high threat', cls: 'warn' },
    consoleLines: [
      { cmd: 'dnstwist', msg: 'Generating domain permutations for acmecorp.com' },
      { info: true, msg: 'Checking TLD swaps, homoglyphs, bitsquats...' },
      { warn: true, msg: '14 registered lookalike domains detected' },
      { warn: true, msg: '13 have active web servers' },
      { warn: true, msg: '11 have active mail servers (phishing risk)' },
      { ok: true, msg: 'Brand risk analysis complete: 11 high, 3 medium' }
    ]
  },
  7: { // Report Compilation
    items: [
      'Risk score: 92/100 (Critical)', 'Vuln score: 1,299.9',
      'Credential score: 46,627.1', 'WAF coverage: 10.9%',
      'Generating executive narrative...', 'Report ready'
    ],
    badge: { text: 'Score: 92', cls: 'alert' },
    consoleLines: [
      { cmd: 'normalize', msg: 'Computing 9-factor weighted risk score' },
      { info: true, msg: 'Vulnerability factor: 1,299.9 (30% weight)' },
      { crit: true, msg: 'Credential exposure factor: 46,627.1 (10% weight)' },
      { warn: true, msg: 'WAF protection: only 10.9% of web assets covered' },
      { info: true, msg: 'Generating executive narrative (7 sections)' },
      { crit: true, msg: 'FINAL RISK SCORE: 92 / 100 \u2014 CRITICAL' },
      { ok: true, msg: 'Intelligence report compiled successfully' }
    ]
  }
};

// ----- Scan Simulation -----
function startScan(domain) {
  state.scanDomain = domain;
  state.phase = 'scanning';

  $('#hero').classList.add('hidden');
  $('#scan-progress').classList.remove('hidden');
  $('#scan-domain-label').textContent = domain;

  renderPhasesList();
  runScanPhases();
}

function renderPhasesList() {
  const container = $('#phases-list');
  container.innerHTML = DEMO_DATA.scanPhases.map((p, i) => `
    <div class="phase-row pending" id="phase-${i}">
      <div class="phase-badge">${i + 1}</div>
      <div class="phase-info">
        <div class="phase-name">${p.name}</div>
        <div class="phase-desc">${p.desc}</div>
        <div class="phase-live-feed" id="phase-feed-${i}"></div>
      </div>
      <div class="phase-status" id="phase-status-${i}"></div>
    </div>
  `).join('');
}

// Console log helper
function consoleLine(obj) {
  const ts = new Date().toISOString().substr(11, 12);
  const body = $('#console-body');
  const line = document.createElement('div');
  line.className = 'console-line';

  if (obj.cmd) {
    line.innerHTML = `<span class="ts">${ts}</span> <span class="cmd">[${obj.cmd}]</span> <span class="info">${obj.msg}</span>`;
  } else if (obj.crit) {
    line.innerHTML = `<span class="ts">${ts}</span> <span class="crit">\u2718 ${obj.msg}</span>`;
  } else if (obj.warn) {
    line.innerHTML = `<span class="ts">${ts}</span> <span class="warn">\u26a0 ${obj.msg}</span>`;
  } else if (obj.ok) {
    line.innerHTML = `<span class="ts">${ts}</span> <span class="ok">\u2714 ${obj.msg}</span>`;
  } else {
    line.innerHTML = `<span class="ts">${ts}</span> <span class="dim">${obj.msg}</span>`;
  }

  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

function runScanPhases() {
  const phases = DEMO_DATA.scanPhases;
  // Randomize durations: 3000–8000ms per phase
  const durations = phases.map(() => 3000 + Math.floor(Math.random() * 5000));
  const totalDuration = durations.reduce((s, d) => s + d, 0);
  let elapsed = 0;

  // Initial console line
  consoleLine({ cmd: 'asp', msg: `Starting attack surface scan for ${state.scanDomain}` });

  function runPhase(index) {
    if (index >= phases.length) {
      consoleLine({ ok: true, msg: 'Scan complete \u2014 preparing results dashboard...' });
      setTimeout(revealResults, 800);
      return;
    }

    const phase = phases[index];
    const dur = durations[index];
    const feed = PHASE_FEEDS[index];
    const row = $(`#phase-${index}`);
    const statusEl = $(`#phase-status-${index}`);
    const feedEl = $(`#phase-feed-${index}`);

    // Activate phase
    row.classList.remove('pending');
    row.classList.add('active');
    statusEl.innerHTML = '<div class="spinner"></div>';

    // Stream live feed items
    const feedItems = feed.items;
    let feedIdx = 0;
    const feedInterval = Math.floor(dur / (feedItems.length + 1));
    const feedTimer = setInterval(() => {
      if (feedIdx < feedItems.length) {
        feedEl.innerHTML = `<span class="feed-item">\u203a ${feedItems[feedIdx]}</span>`;
        feedIdx++;
      }
    }, feedInterval);

    // Stream console lines
    const consoleItems = feed.consoleLines;
    let consoleIdx = 0;
    const consoleInterval = Math.floor(dur / (consoleItems.length + 1));
    const consoleTimer = setInterval(() => {
      if (consoleIdx < consoleItems.length) {
        consoleLine(consoleItems[consoleIdx]);
        consoleIdx++;
      }
    }, consoleInterval);

    // Progress bar animation
    const startElapsed = elapsed;
    const startTime = performance.now();

    function tick() {
      const now = performance.now();
      const dt = now - startTime;
      const phaseProgress = Math.min(dt / dur, 1);
      const currentElapsed = startElapsed + dur * phaseProgress;
      const pct = Math.min((currentElapsed / totalDuration) * 100, 100);

      $('#progress-bar').style.width = pct + '%';
      $('#progress-pct').textContent = Math.round(pct) + '%';

      if (phaseProgress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);

    // Phase complete
    setTimeout(() => {
      clearInterval(feedTimer);
      clearInterval(consoleTimer);
      elapsed += dur;

      row.classList.remove('active');
      row.classList.add('complete');
      feedEl.innerHTML = '';
      statusEl.innerHTML = '<span class="checkmark">\u2713</span>';

      // Add result badge to phase name
      if (feed.badge) {
        const nameEl = row.querySelector('.phase-name');
        nameEl.innerHTML += ` <span class="phase-result-badge ${feed.badge.cls}">${feed.badge.text}</span>`;
      }

      runPhase(index + 1);
    }, dur);
  }

  runPhase(0);
}

// ----- Results Reveal -----
function revealResults() {
  state.phase = 'results';
  $('#scan-progress').classList.add('hidden');
  $('#results-container').classList.remove('hidden');
  $('#results-domain').textContent = state.scanDomain;

  renderStatCards();
  renderEndpoints();
  renderBreaches();
  renderSubdomains();
  renderPorts();
  renderTechnologies();
  renderSSL();
  renderTyposquats();

  const sections = $$('.anim-section');
  sections.forEach((el, i) => {
    setTimeout(() => el.classList.add('visible'), 150 * i);
  });

  // Animate risk gauge ring + number
  setTimeout(() => {
    const score = DEMO_DATA.risk_score;
    const circumference = 2 * Math.PI * 52;
    const offset = circumference * (1 - score / 100);
    const fill = $('#gauge-fill');
    fill.style.strokeDashoffset = offset;
    animateValue($('#risk-gauge-value'), 0, score, 1800);
  }, 300);

  // Animate stat card numbers
  setTimeout(() => {
    $$('.stat-card-value[data-target]').forEach(el => {
      animateValue(el, 0, parseInt(el.dataset.target), 1200);
    });
  }, 200);
}

// ----- Stat Cards -----
function renderStatCards() {
  const container = $('#stat-cards');
  container.innerHTML = DEMO_DATA.statCards.map(card => `
    <div class="stat-card" data-link="${card.link}">
      <div class="stat-card-icon-wrap" style="color:${card.color}">${icon(card.icon)}</div>
      <div class="stat-card-value" style="color:${card.color}" data-target="${card.value}">0</div>
      <div class="stat-card-label">${card.label}</div>
      <div class="stat-card-sub">${card.sub}</div>
    </div>
  `).join('');

  container.querySelectorAll('.stat-card[data-link]').forEach(card => {
    card.addEventListener('click', () => {
      const target = document.getElementById(card.dataset.link);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

// ----- Endpoints Table -----
function renderEndpoints() {
  const d = DEMO_DATA;
  const visible = d.endpoints.slice(0, 5);
  const remaining = d.endpoints_total - visible.length;
  $('#endpoints-count').textContent = d.endpoints_total + ' total';

  let html = `<div class="fade-mask"><table class="data-table">
    <thead><tr>
      <th>URL</th><th>Title</th><th>Vulnerabilities</th>
    </tr></thead><tbody>`;

  visible.forEach(e => {
    html += `<tr>
      <td class="url-cell">${escHtml(e.url)}</td>
      <td>${escHtml(e.title)}</td>
      <td><div class="vuln-counts">
        ${e.vulns.c ? `<span class="vuln-count c">${e.vulns.c} C</span>` : ''}
        ${e.vulns.h ? `<span class="vuln-count h">${e.vulns.h} H</span>` : ''}
        ${e.vulns.m ? `<span class="vuln-count m">${e.vulns.m} M</span>` : ''}
        ${!e.vulns.c && !e.vulns.h && !e.vulns.m ? '<span style="color:var(--text-dim)">\u2014</span>' : ''}
      </div></td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += teaserRow(remaining, 'more endpoints with vulnerabilities');
  $('#endpoints-table').innerHTML = html;
}

// ----- Breaches Table -----
function renderBreaches() {
  const d = DEMO_DATA;
  const remaining = d.breaches_total - d.breaches.length;
  $('#breaches-count').textContent = d.breaches_total + ' total';

  let html = `<div class="fade-mask"><table class="data-table">
    <thead><tr>
      <th>Email</th><th>Source</th><th>Data Type</th><th>Risk</th><th>Date</th>
    </tr></thead><tbody>`;

  d.breaches.forEach(b => {
    const [local, domain] = b.email.split('@');
    html += `<tr>
      <td class="url-cell"><span class="blurred-text">${escHtml(local)}</span>@${escHtml(domain)}</td>
      <td>${escHtml(b.source)}</td>
      <td>${escHtml(b.dataType)}</td>
      <td><span class="severity-badge severity-${b.risk}">${capitalize(b.risk)}</span></td>
      <td>${b.date}</td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += teaserRow(remaining, 'more credential exposures detected');
  $('#breaches-table').innerHTML = html;
}

// ----- Subdomains Table -----
function renderSubdomains() {
  const d = DEMO_DATA;
  const remaining = d.subdomains_total - d.subdomains.length;
  $('#subdomains-count').textContent = d.subdomains_total.toLocaleString() + ' total';

  let html = `<div class="fade-mask"><table class="data-table">
    <thead><tr>
      <th>Subdomain</th><th>Status</th><th>IP Address</th>
    </tr></thead><tbody>`;

  d.subdomains.forEach(s => {
    html += `<tr>
      <td class="url-cell">${escHtml(s.name)}</td>
      <td><span class="status-dot ${s.status}">${capitalize(s.status)}</span></td>
      <td style="font-family:var(--mono);font-size:0.78rem;color:var(--text-muted)">${s.ip}</td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += teaserRow(remaining.toLocaleString(), 'more subdomains discovered');
  $('#subdomains-table').innerHTML = html;
}

// ----- Ports Table -----
function renderPorts() {
  const d = DEMO_DATA;
  const remaining = d.ports_total - d.ports.length;
  $('#ports-count').textContent = d.ports_total + ' total';

  let html = `<div class="fade-mask"><table class="data-table">
    <thead><tr>
      <th>Host</th><th>Port</th><th>Service</th>
    </tr></thead><tbody>`;

  d.ports.forEach(p => {
    html += `<tr>
      <td style="font-family:var(--mono);font-size:0.76rem;color:var(--text-secondary)">${escHtml(p.host)}</td>
      <td><span style="font-family:var(--mono);font-weight:600;color:var(--text-primary)">${p.port}</span></td>
      <td>${escHtml(p.service)} <span style="color:var(--text-muted);font-size:0.76rem">/ ${escHtml(p.product)}</span></td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += teaserRow(remaining, 'more exposed services found');
  $('#ports-table').innerHTML = html;
}

// ----- Technologies Grid -----
function renderTechnologies() {
  const d = DEMO_DATA;
  const remaining = d.technologies_total - d.technologies.length;
  $('#tech-count').textContent = d.technologies_total + ' total';

  let html = '';
  d.technologies.forEach(t => {
    html += `<div class="tech-chip">
      <span class="tech-chip-icon">${icon(t.icon)}</span>
      <span class="tech-chip-name">${escHtml(t.name)}</span>
      ${t.version ? `<span class="tech-chip-version">${escHtml(t.version)}</span>` : ''}
    </div>`;
  });

  html += `<div class="tech-teaser">${icon('lockSmall')} <span class="teaser-count">${remaining}</span> more technologies detected</div>`;
  $('#tech-grid').innerHTML = html;
}

// ----- SSL Certificates Table -----
function renderSSL() {
  const d = DEMO_DATA;
  const remaining = d.certificates_total - d.certificates.length;
  $('#ssl-count').textContent = d.certificates_total + ' total';

  let html = `<div class="fade-mask"><table class="data-table">
    <thead><tr>
      <th>Domain</th><th>Expiry</th><th>Status</th><th>Issuer</th><th>Issues</th>
    </tr></thead><tbody>`;

  d.certificates.forEach(c => {
    html += `<tr>
      <td class="url-cell">${escHtml(c.domain)}</td>
      <td>${c.expiry}</td>
      <td><span class="status-dot ${c.status}">${capitalize(c.status)}</span></td>
      <td>${escHtml(c.issuer)}</td>
      <td>${c.issues === 'None' ? '<span style="color:var(--text-dim)">\u2014</span>' : `<span style="color:var(--medium)">${escHtml(c.issues)}</span>`}</td>
    </tr>`;
  });

  html += `</tbody></table></div>`;
  html += teaserRow(remaining, 'more certificates found');
  $('#ssl-table').innerHTML = html;
}

// ----- Typosquats Table -----
function renderTyposquats() {
  const d = DEMO_DATA;
  $('#typosquats-count').textContent = d.typosquats_total + ' total';

  let html = `<table class="data-table">
    <thead><tr>
      <th>Domain</th><th>Category</th><th>Threat</th><th>Web</th><th>MX</th><th>Note</th>
    </tr></thead><tbody>`;

  // Show first 8 in table, rest as teaser
  const visible = d.typosquats.slice(0, 8);
  const remaining = d.typosquats_total - visible.length;

  visible.forEach(t => {
    const sevClass = t.threat === 'high' ? 'high' : 'medium';
    html += `<tr>
      <td class="url-cell">${escHtml(t.domain)}</td>
      <td><span class="severity-badge severity-info">${escHtml(t.category)}</span></td>
      <td><span class="severity-badge severity-${sevClass}">${capitalize(t.threat)}</span></td>
      <td>${t.hasWeb ? '<span class="check-yes">\u2713</span>' : '<span class="check-no">\u2715</span>'}</td>
      <td>${t.hasMX ? '<span class="check-yes">\u2713</span>' : '<span class="check-no">\u2715</span>'}</td>
      <td style="font-size:0.76rem;color:var(--text-muted)">${escHtml(t.note)}</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  if (remaining > 0) {
    html += `<div class="teaser-row">${icon('lockSmall')} <span><span class="teaser-count">${remaining}</span> more lookalike domains detected</span></div>`;
  }
  $('#typosquats-table').innerHTML = html;
}

// ----- Teaser Row Helper -----
function teaserRow(count, label) {
  return `<div class="teaser-row">
    ${icon('lockSmall')}
    <span><span class="teaser-count">${count}</span> ${label}</span>
  </div>`;
}

// ----- Number Animation -----
function animateValue(el, start, end, duration) {
  const startTime = performance.now();
  function tick(now) {
    const t = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    const current = Math.round(start + (end - start) * eased);
    el.textContent = current.toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ----- Lead Capture -----
function handleLeadCapture(e) {
  e.preventDefault();
  showToast('Thank you! We\u2019ll be in touch with your full report.');
}

// ----- Toast -----
function showToast(message) {
  const container = $('#toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast toast-success';
  toast.innerHTML = `${icon('checkCircle')} <span>${escHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3200);
}

// ----- Tooltip Positioning -----
document.addEventListener('mouseover', (e) => {
  const tip = e.target.closest('.info-tip');
  if (!tip) return;
  const rect = tip.getBoundingClientRect();
  tip.style.setProperty('--tip-top', (rect.bottom + 10) + 'px');
  tip.style.setProperty('--tip-left', Math.max(16, Math.min(rect.left - 10, window.innerWidth - 340)) + 'px');
});

// ----- Domain Validation -----
function isValidDomain(str) {
  // Must have at least one dot, no spaces, TLD 2+ chars, labels 1-63 chars
  const re = /^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;
  return re.test(str) && str.length <= 253;
}

// ----- Utilities -----
function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
