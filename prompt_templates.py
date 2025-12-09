"""
Optimized prompts with intelligent certificate parsing and few-shot examples.
"""
from typing import List, Tuple
import re


class PromptTemplates:
    """Enhanced prompts with certificate field extraction."""
    
    # Few-shot examples with ONLY meaningful fields
    FEW_SHOT_EXAMPLES = """
=== EXAMPLE 1: PHISHING ===
CERTIFICATE ID: 0
URL: https://newrecipient-device-confirmation.com/Login.php
Domain: newrecipient-device-confirmation.com
Issuer: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
Certificate Type: Domain Validation (DV)
SANs: newrecipient-device-confirmation.com, www.newrecipient-device-confirmation.com

ANALYSIS:
{{"id": 0, "label": "phishing", "confidence": 0.95, "reasoning": "Domain uses suspicious compound pattern 'newrecipient-device-confirmation' mimicking banking security flow. Path '/Login.php' is classic phishing. Uses DV certificate from Sectigo (common for phishing). Domain has no legitimate organization.", "red_flags": ["suspicious_compound_domain", "banking_keywords", "login_page", "dv_certificate", "no_organization"]}}

=== EXAMPLE 2: PHISHING ===
CERTIFICATE ID: 1
URL: https://polkakesvvep-trade.com
Domain: polkakesvvep-trade.com
Issuer: C=US, O=Let's Encrypt, CN=R3
Certificate Type: Domain Validation (DV)
SANs: polkakesvvep-trade.com, www.polkakesvvep-trade.com

ANALYSIS:
{{"id": 1, "label": "phishing", "confidence": 0.92, "reasoning": "Domain contains nonsense 'kesvvep' likely typosquatting Polkadot/crypto. Combined with 'trade' keyword = common crypto scam pattern. Free Let's Encrypt certificate. No organization info.", "red_flags": ["crypto_typosquatting", "nonsense_string", "trade_keyword", "free_certificate"]}}

=== EXAMPLE 3: PHISHING ===
CERTIFICATE ID: 2
URL: https://kalnaholychild.in/psyy/pre_qualify.php
Domain: kalnaholychild.in
Issuer: C=US, ST=TX, L=Houston, O=cPanel Inc., CN=cPanel Inc. Certification Authority
Certificate Type: Domain Validation (DV)
SANs: cpanel.kalnaholychild.in, cpcalendars.kalnaholychild.in, cpcontacts.kalnaholychild.in, mail.kalnaholychild.in, webdisk.kalnaholychild.in, webmail.kalnaholychild.in

ANALYSIS:
{{"id": 2, "label": "phishing", "confidence": 0.88, "reasoning": "Compromised shared hosting (cPanel SANs exposed). Suspicious path '/psyy/pre_qualify.php' with random string. Legitimate sites don't expose cPanel infrastructure. Phishing page uploaded to hacked site.", "red_flags": ["compromised_hosting", "cpanel_exposed", "suspicious_path", "random_string", "phishing_page_name"]}}

=== EXAMPLE 4: PHISHING ===
CERTIFICATE ID: 3
URL: https://volksban-k-de.com/
Domain: volksban-k-de.com
Issuer: C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
Certificate Type: Domain Validation (DV)
SANs: volksban-k-de.com, www.volksban-k-de.com

ANALYSIS:
{{"id": 3, "label": "phishing", "confidence": 0.93, "reasoning": "Typosquatting 'Volksbank' (German bank) with hyphens 'volksban-k-de' instead of 'volksbank.de'. Uses hyphens to mimic domain structure. DV certificate from Sectigo. Banking brand impersonation.", "red_flags": ["bank_typosquatting", "hyphen_confusion", "german_bank_impersonation", "dv_certificate", "brand_impersonation"]}}

=== EXAMPLE 5: BENIGN ===
CERTIFICATE ID: 4
URL: https://www.google.com
Domain: www.google.com
Issuer: C=US, O=Google Trust Services LLC, CN=GTS CA 1C3
Certificate Type: Organization Validation (OV)
Organization: Google LLC
SANs: www.google.com, *.google.com, *.appengine.google.com, *.cloud.google.com, *.google-analytics.com

ANALYSIS:
{{"id": 4, "label": "benign", "confidence": 0.98, "reasoning": "Legitimate Google certificate. Proper organization 'Google LLC' matches domain owner. OV certificate from Google's own CA 'Google Trust Services'. Appropriate wildcard SANs for Google services.", "red_flags": []}}
"""
    
    # Enhanced batch prompt
    BATCH_PROMPT = """You are an expert cybersecurity analyst specializing in TLS certificate phishing detection.

KEY PHISHING INDICATORS:
1. **Typosquatting**: paypa1.com (1→l), g00gle.com (0→o), micros0ft.com
2. **Hyphen confusion**: volksban-k-de.com (volksbank.de), pay-pal.com
3. **Suspicious compounds**: secure-login-verify-account.com, update-payment-confirm.com
4. **Brand impersonation**: Domain mimics bank/company but wrong TLD or structure
5. **Free DV certificates**: Let's Encrypt, Sectigo DV for major brands (real companies use OV/EV)
6. **Compromised hosting**: cPanel/webmail subdomains in SANs, suspicious paths
7. **Security keywords**: verify, secure, confirm, update, login, account combined with brand names
8. **Random strings**: Nonsense characters, excessive numbers

LEARN FROM THESE EXAMPLES:
{examples}

NOW ANALYZE THESE {count} CERTIFICATES:

{certificates}

CRITICAL INSTRUCTIONS:
- Output ONLY a JSON array
- NO markdown, NO code blocks, NO explanatory text
- Each object needs: id, label ("phishing" or "benign"), confidence (0.0-1.0), reasoning, red_flags
- Return exactly {count} results in order

JSON OUTPUT:
[
  {{"id": 0, "label": "phishing", "confidence": 0.85, "reasoning": "specific evidence", "red_flags": ["flag1", "flag2"]}},
  {{"id": 1, "label": "benign", "confidence": 0.92, "reasoning": "why legitimate", "red_flags": []}}
]"""

    @staticmethod
    def extract_meaningful_fields(cert_content: str) -> str:
        """
        Extract only meaningful fields from certificate for LLM analysis.
        Removes the base64 certificate body which is not useful for phishing detection.
        """
        # Remove certificate body (between BEGIN and END CERTIFICATE)
        cert_cleaned = re.sub(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            '',
            cert_content,
            flags=re.DOTALL
        )
        
        # Extract key fields
        extracted = []
        
        # Extract URL (most important)
        url_match = re.search(r'https?://[^\s]+', cert_content)
        if url_match:
            extracted.append(f"URL: {url_match.group(0)}")
        
        # Extract Subject (CN = domain)
        subject_match = re.search(r'subject[=\s]+(.+?)(?:\n|issuer)', cert_cleaned, re.IGNORECASE)
        if subject_match:
            subject = subject_match.group(1).strip()
            extracted.append(f"Subject: {subject}")
            
            # Extract just the domain from CN
            cn_match = re.search(r'CN\s*=\s*([^\s,]+)', subject)
            if cn_match:
                extracted.append(f"Domain: {cn_match.group(1)}")
        
        # Extract Issuer (CA information)
        issuer_match = re.search(r'issuer[=\s]+(.+?)(?:\n|$)', cert_cleaned, re.IGNORECASE)
        if issuer_match:
            issuer = issuer_match.group(1).strip()
            extracted.append(f"Issuer: {issuer}")
            
            # Determine certificate type
            if 'Domain Validation' in issuer or issuer_match.group(0).count('=') <= 3:
                extracted.append("Certificate Type: Domain Validation (DV)")
            elif 'Organization Validation' in issuer or 'O=' in issuer:
                extracted.append("Certificate Type: Organization Validation (OV)")
            elif 'Extended Validation' in issuer or 'EV' in issuer:
                extracted.append("Certificate Type: Extended Validation (EV)")
            else:
                extracted.append("Certificate Type: Domain Validation (DV)")
        
        # Extract Organization if present
        org_match = re.search(r'O\s*=\s*([^,\n]+)', cert_content)
        if org_match and 'Sectigo' not in org_match.group(1) and 'Let\'s Encrypt' not in org_match.group(1):
            extracted.append(f"Organization: {org_match.group(1).strip()}")
        
        # Extract Subject Alternative Names (SANs)
        san_section = re.search(r'Subject Alternative.*?\n(.*?)(?:\n\n|\Z)', cert_content, re.DOTALL | re.IGNORECASE)
        if san_section:
            san_text = san_section.group(1)
            # Extract domains from SANs
            san_domains = re.findall(r'DNS:([^\s,]+)', san_text)
            if not san_domains:
                # Try alternative format
                san_domains = re.findall(r'(?:^|\s)([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:\s|,|$)', san_text)
            
            if san_domains:
                extracted.append(f"SANs: {', '.join(san_domains[:10])}")  # Limit to 10 SANs
        
        # Extract validity period
        validity_match = re.search(r'Not Before:\s*(.+?)\s+Not After:\s*(.+?)(?:\n|$)', cert_content)
        if validity_match:
            extracted.append(f"Valid: {validity_match.group(1)} to {validity_match.group(2)}")
        
        # Check for suspicious paths in URL
        if url_match:
            url = url_match.group(0)
            path_match = re.search(r'https?://[^/]+(/[^\s]*)', url)
            if path_match and path_match.group(1) not in ['/', '']:
                extracted.append(f"Path: {path_match.group(1)}")
        
        return '\n'.join(extracted)
    
    @staticmethod
    def format_batch(cert_data_list: List[Tuple[int, str]]) -> str:
        """
        Format multiple certificates with only meaningful fields.
        
        Args:
            cert_data_list: List of (index, certificate_content) tuples
        
        Returns:
            Formatted prompt string with extracted fields only
        """
        certs_text = ""
        for idx, content in cert_data_list:
            # Extract meaningful fields only
            meaningful_content = PromptTemplates.extract_meaningful_fields(content)
            certs_text += f"\nCERTIFICATE ID: {idx}\n{meaningful_content}\n"
        
        return PromptTemplates.BATCH_PROMPT.format(
            examples=PromptTemplates.FEW_SHOT_EXAMPLES,
            count=len(cert_data_list),
            certificates=certs_text
        )
    
    @staticmethod
    def truncate_certificate(cert_content: str, max_length: int = 3000) -> str:
        """
        No longer needed since we extract only meaningful fields.
        But kept for backward compatibility.
        """
        # Just return as-is since extract_meaningful_fields handles everything
        return cert_content
