"""
Optimized prompts with few-shot examples for better accuracy.
"""
from typing import List, Tuple


class PromptTemplates:
    """Enhanced prompts with few-shot learning for phishing detection."""
    
    # Few-shot examples for better learning
    FEW_SHOT_EXAMPLES = """
=== EXAMPLE 1: PHISHING ===
CERTIFICATE ID: 0
Content: CN = newrecipient-device-confirmation.com
Issuer: C = GB, ST = Greater Manchester, L = Salford, O = Sectigo Limited, CN = Sectigo RSA Domain Validation Secure Server CA
Certificate chain: Sectigo RSA Domain Validation Secure Server CA

ANALYSIS:
{{"id": 0, "label": "phishing", "confidence": 0.95, "reasoning": "Domain 'newrecipient-device-confirmation.com' uses suspicious pattern mimicking banking/payment services with 'recipient', 'device', and 'confirmation' keywords. Legitimate services don't use such generic compound domains. Uses DV certificate from Sectigo which is common for phishing.", "red_flags": ["suspicious_compound_domain", "mimics_banking_language", "generic_security_terms", "dv_certificate"]}}

=== EXAMPLE 2: PHISHING ===
CERTIFICATE ID: 1
Content: CN = polkakesvvep-trade.com
Issuer: C = US, O = Let's Encrypt, CN = R3
Certificate chain: Let's Encrypt R3

ANALYSIS:
{{"id": 1, "label": "phishing", "confidence": 0.92, "reasoning": "Domain 'polkakesvvep-trade.com' contains nonsense string 'kesvvep' which is likely typosquatting of 'Polka' cryptocurrency. The term 'trade' combined with crypto-related name is a common phishing pattern. Uses free Let's Encrypt certificate which attackers frequently use.", "red_flags": ["crypto_typosquatting", "nonsense_characters", "trade_keyword", "free_certificate"]}}

=== EXAMPLE 3: PHISHING ===
CERTIFICATE ID: 2
Content: CN = kalnaholychild.in
URL: https://kalnaholychild.in/psyy/pre_qualify.php
Issuer: C = US, ST = TX, L = Houston, O = "cPanel, Inc.", CN = "cPanel, Inc. Certification Authority"
Subject Alternative Names: cpanel.kalnaholychild.in, cpcalendars.kalnaholychild.in, cpcontacts.kalnaholychild.in, mail.kalnaholychild.in

ANALYSIS:
{{"id": 2, "label": "phishing", "confidence": 0.88, "reasoning": "Domain 'kalnaholychild.in' appears to be compromised hosting (cPanel infrastructure exposed in SANs). The path '/psyy/pre_qualify.php' is highly suspicious - legitimate sites don't use random strings like 'psyy' and 'pre_qualify.php' is typical phishing page name. Multiple cPanel subdomains in SANs indicate compromised shared hosting.", "red_flags": ["suspicious_path", "compromised_hosting", "cpanel_exposed", "phishing_page_pattern", "random_path_string"]}}

=== EXAMPLE 4: BENIGN ===
CERTIFICATE ID: 3
Content: CN = www.google.com
Issuer: C = US, O = Google Trust Services LLC, CN = GTS CA 1C3
Subject Alternative Names: www.google.com, *.google.com, *.appengine.google.com, *.cloud.google.com

ANALYSIS:
{{"id": 3, "label": "benign", "confidence": 0.98, "reasoning": "Legitimate Google certificate with proper organization 'Google Trust Services LLC', matching domain name, and appropriate wildcard SANs for Google services. EV/OV certificate from Google's own CA.", "red_flags": []}}
"""
    
    # Enhanced batch prompt with few-shot examples
    BATCH_PROMPT = """You are an expert cybersecurity analyst specializing in TLS certificate phishing detection. You will analyze certificates and identify phishing attempts based on domain patterns, certificate authorities, and contextual clues.

KEY PHISHING INDICATORS:
1. **Typosquatting**: paypa1.com (1 instead of l), g00gle.com (0 instead of o)
2. **Suspicious compounds**: secure-login-verify-account.com, update-payment-confirm.com
3. **Brand impersonation**: Domain doesn't match Organization field (CN=paypal-secure.com, O=Random Company)
4. **Free certificates for brands**: Let's Encrypt or similar free CA for major companies
5. **Compromised hosting**: cPanel/webmail subdomains exposed, suspicious paths like /update/login.php
6. **Unusual patterns**: Random strings, excessive hyphens, security-themed keywords (verify, secure, confirm, update)

LEARN FROM THESE EXAMPLES:
{examples}

NOW ANALYZE THESE {count} CERTIFICATES:

{certificates}

CRITICAL INSTRUCTIONS:
1. Output ONLY a JSON array, no other text
2. No markdown code blocks (no ```)
3. Each object must have: id, label, confidence, reasoning, red_flags
4. Label must be exactly "phishing" or "benign"
5. Confidence is 0.0 to 1.0
6. Return exactly {count} results in order

OUTPUT FORMAT:
[
  {{"id": 0, "label": "phishing", "confidence": 0.85, "reasoning": "specific evidence here", "red_flags": ["flag1", "flag2"]}},
  {{"id": 1, "label": "benign", "confidence": 0.92, "reasoning": "why it's legitimate", "red_flags": []}}
]"""

    @staticmethod
    def format_batch(cert_data_list: List[Tuple[int, str]]) -> str:
        """
        Format multiple certificates for batch processing with few-shot examples.
        
        Args:
            cert_data_list: List of (index, certificate_content) tuples
        
        Returns:
            Formatted prompt string with examples
        """
        certs_text = ""
        for idx, content in cert_data_list:
            certs_text += f"\nCERTIFICATE ID: {idx}\n{content}\n"
        
        return PromptTemplates.BATCH_PROMPT.format(
            examples=PromptTemplates.FEW_SHOT_EXAMPLES,
            count=len(cert_data_list),
            certificates=certs_text
        )
    
    @staticmethod
    def truncate_certificate(cert_content: str, max_length: int = 3000) -> str:
        """
        Intelligently truncate certificate content while preserving key fields.
        """
        if len(cert_content) <= max_length:
            return cert_content
        
        # Extract key information that should always be preserved
        lines = cert_content.split('\n')
        important_lines = []
        other_lines = []
        
        important_keywords = [
            'CN =', 'Subject:', 'Issuer:', 'issuer=', 'subject=',
            'Certificate chain', 'Subject Alternative', 'Organization',
            'URL', 'Domain', 'O =', 'OU ='
        ]
        
        for line in lines:
            if any(keyword in line for keyword in important_keywords):
                important_lines.append(line)
            else:
                other_lines.append(line)
        
        # Always include important lines
        result = '\n'.join(important_lines)
        
        # Add other lines if there's space
        remaining_space = max_length - len(result)
        if remaining_space > 100 and other_lines:
            # Add beginning of other content
            other_text = '\n'.join(other_lines)
            if len(other_text) <= remaining_space:
                result += '\n' + other_text
            else:
                # Add truncated portion
                result += '\n' + other_text[:remaining_space - 50] + '\n[...TRUNCATED...]'
        
        return result
