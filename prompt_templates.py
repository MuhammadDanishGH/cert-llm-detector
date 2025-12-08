"""
Optimized prompts for batch processing multiple certificates.
"""
from typing import List, Tuple

class PromptTemplates:
    """Ultra-compressed prompts for maximum throughput."""
    
    # Batch prompt - processes multiple certificates in ONE API call
    BATCH_PROMPT = """Analyze these {count} TLS certificates for phishing indicators. For each certificate, check:
- Domain typosquatting/homographs (e.g., paypa1.com, g00gle.com)
- Organization-domain mismatches
- Suspicious CAs for claimed brands
- Unusual validity periods or SANs

{certificates}

Respond with a JSON array (no markdown, no code blocks):
[
  {{"id": 0, "label": "phishing" or "benign", "confidence": 0.0-1.0, "reasoning": "brief explanation", "red_flags": ["flag1", "flag2"]}},
  {{"id": 1, "label": "phishing" or "benign", "confidence": 0.0-1.0, "reasoning": "brief explanation", "red_flags": []}},
  ...
]

IMPORTANT: Return exactly {count} results in the same order as input."""

    @staticmethod
    def format_batch(cert_data_list: List[Tuple[int, str]]) -> str:
        """
        Format multiple certificates for batch processing.
        
        Args:
            cert_data_list: List of (index, certificate_content) tuples
        
        Returns:
            Formatted prompt string
        """
        certs_text = ""
        for idx, content in cert_data_list:
            certs_text += f"\n{'='*60}\nCERTIFICATE ID: {idx}\n{'='*60}\n{content}\n"
        
        return PromptTemplates.BATCH_PROMPT.format(
            count=len(cert_data_list),
            certificates=certs_text
        )
    
    @staticmethod
    def truncate_certificate(cert_content: str, max_length: int = 3000) -> str:
        """Intelligently truncate certificate content."""
        if len(cert_content) <= max_length:
            return cert_content
        
        # Keep subject/issuer (beginning) and extensions (end)
        keep_start = int(max_length * 0.6)
        keep_end = int(max_length * 0.4)
        
        return (
            cert_content[:keep_start] + 
            "\n[...TRUNCATED...]\n" + 
            cert_content[-keep_end:]
        )