"""
Prompt templates for LLM-based certificate analysis.
Designed to extract semantic and linguistic anomalies from TLS certificates.
"""

class PromptTemplates:
    """Collection of prompts for certificate phishing detection."""
    
    CERTIFICATE_ANALYSIS_PROMPT = """You are an expert cybersecurity analyst specializing in TLS certificate fraud detection. Analyze the following TLS certificate for signs of phishing or malicious intent.

**CERTIFICATE CONTENT:**
```
{certificate_content}
```

**ANALYSIS TASK:**
Evaluate this certificate for the following red flags:

1. **Domain Name Anomalies**:
   - Homograph attacks (e.g., paypa1.com instead of paypal.com)
   - Typosquatting patterns (e.g., gooogle.com, amaz0n.com)
   - Suspicious TLDs or long subdomain chains
   - Brand impersonation attempts

2. **Organizational Field Inconsistencies**:
   - Organization name doesn't match the domain
   - Generic or fake-sounding organization names
   - Mismatched geographical information
   - Missing or incomplete organizational data

3. **Linguistic Abnormalities**:
   - Grammatical errors or unnatural phrasing
   - Machine-generated or template-like text
   - Character encoding anomalies
   - Unusual punctuation or formatting

4. **Certificate Metadata Concerns**:
   - Extremely short validity periods
   - Unusual certificate authorities for the claimed organization
   - Multiple unrelated domains in Subject Alternative Names (SAN)
   - Free/automated certificate patterns for enterprise brands

5. **Contextual Red Flags**:
   - High-value brand certificate from unknown CA
   - Consumer domain using Enterprise Validation (EV)
   - Mismatched certificate type vs. domain purpose

**OUTPUT FORMAT:**
Respond with ONLY a valid JSON object (no markdown, no code blocks):
{{
    "label": "phishing" or "benign",
    "confidence": <float between 0.0 and 1.0>,
    "reasoning": "<concise explanation of your decision>",
    "red_flags": [<list of specific concerns found>],
    "domain_analysis": "<evaluation of the primary domain>",
    "organization_analysis": "<evaluation of organizational fields>"
}}

**IMPORTANT**: 
- Be precise and evidence-based
- A certificate can be technically valid but still used for phishing
- Consider the entire context, not just individual fields
- Confidence should reflect certainty of your assessment
"""

    FALLBACK_ANALYSIS_PROMPT = """Analyze this TLS certificate and determine if it's likely used for phishing.

CERTIFICATE:
{certificate_content}

Respond with JSON only:
{{
    "label": "phishing" or "benign",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}
"""

    BATCH_SUMMARY_PROMPT = """You've analyzed {count} TLS certificates. Summarize the key patterns you observed in phishing certificates vs. benign ones.

Focus on:
1. Most common phishing tactics
2. Typical benign certificate characteristics
3. Edge cases or difficult decisions

Keep response under 200 words.
"""

    @staticmethod
    def format_certificate_prompt(cert_content: str, use_fallback: bool = False) -> str:
        """Format the certificate analysis prompt with content."""
        template = (
            PromptTemplates.FALLBACK_ANALYSIS_PROMPT 
            if use_fallback 
            else PromptTemplates.CERTIFICATE_ANALYSIS_PROMPT
        )
        return template.format(certificate_content=cert_content)