#!/usr/bin/env python3
"""
LLM-Based TLS Certificate Phishing Detection System
Main execution script for certificate analysis using Gemini API.
"""

import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

import google.generativeai as genai
import pandas as pd
from tqdm import tqdm

from config import Config
from prompt_templates import PromptTemplates


class CertificateDetector:
    """Main class for LLM-based certificate phishing detection."""
    
    def __init__(self):
        """Initialize the detector with Gemini API."""
        Config.validate()
        
        # Configure Gemini
        genai.configure(api_key=Config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel(Config.GEMINI_MODEL)
        
        # Setup logging
        self._setup_logging()
        
        # Statistics
        self.stats = {
            "total_processed": 0,
            "phishing_detected": 0,
            "benign_detected": 0,
            "errors": 0,
            "api_calls": 0
        }
    
    def _setup_logging(self):
        """Configure logging to file and console."""
        log_file = Config.LOGS_DIR / f"detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_certificate(self, cert_path: Path) -> Optional[str]:
        """Load and validate a certificate file."""
        try:
            if cert_path.stat().st_size > Config.MAX_CERT_SIZE:
                self.logger.warning(f"Certificate too large: {cert_path.name}")
                return None
            
            with open(cert_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return content if content.strip() else None
            
        except Exception as e:
            self.logger.error(f"Error loading {cert_path.name}: {e}")
            return None
    
    def analyze_certificate(self, cert_content: str, cert_name: str) -> Optional[Dict]:
        """Analyze a certificate using Gemini API."""
        prompt = PromptTemplates.format_certificate_prompt(cert_content)
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                # Rate limiting
                time.sleep(Config.REQUEST_DELAY_SECONDS)
                
                response = self.model.generate_content(prompt)
                self.stats["api_calls"] += 1
                
                # Extract JSON from response
                result = self._parse_llm_response(response.text)
                
                if result:
                    return result
                
                self.logger.warning(f"Failed to parse response for {cert_name}, attempt {attempt + 1}")
                
            except Exception as e:
                self.logger.error(f"API error for {cert_name} (attempt {attempt + 1}): {e}")
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY * (attempt + 1))
        
        # Return fallback prediction
        self.stats["errors"] += 1
        return {
            "label": "benign",
            "confidence": 0.0,
            "reasoning": "Error during analysis - defaulting to benign",
            "red_flags": [],
            "domain_analysis": "N/A",
            "organization_analysis": "N/A"
        }
    
    def _parse_llm_response(self, response_text: str) -> Optional[Dict]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        try:
            # Remove markdown code blocks if present
            text = response_text.strip()
            if text.startswith("```"):
                # Extract content between code fences
                lines = text.split('\n')
                text = '\n'.join(lines[1:-1] if len(lines) > 2 else lines)
            
            # Clean up common JSON issues
            text = text.replace("```json", "").replace("```", "").strip()
            
            result = json.loads(text)
            
            # Validate required fields
            if "label" in result and "confidence" in result and "reasoning" in result:
                # Normalize label
                result["label"] = result["label"].lower()
                if result["label"] not in ["phishing", "benign"]:
                    result["label"] = "benign"
                
                # Ensure confidence is float
                result["confidence"] = float(result["confidence"])
                
                return result
            
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            self.logger.debug(f"JSON parse error: {e}")
        
        return None
    
    def process_certificates(self, cert_dir: Path, true_label: str) -> List[Dict]:
        """Process all certificates in a directory."""
        results = []
        cert_files = list(cert_dir.glob("*"))
        
        self.logger.info(f"Processing {len(cert_files)} {true_label} certificates from {cert_dir.name}")
        
        for cert_path in tqdm(cert_files, desc=f"Analyzing {true_label} certs"):
            cert_content = self.load_certificate(cert_path)
            
            if not cert_content:
                continue
            
            prediction = self.analyze_certificate(cert_content, cert_path.name)
            
            if prediction:
                result = {
                    "filename": cert_path.name,
                    "true_label": true_label,
                    "predicted_label": prediction["label"],
                    "confidence": prediction["confidence"],
                    "reasoning": prediction["reasoning"],
                    "red_flags": json.dumps(prediction.get("red_flags", [])),
                    "domain_analysis": prediction.get("domain_analysis", ""),
                    "organization_analysis": prediction.get("organization_analysis", ""),
                    "timestamp": datetime.now().isoformat()
                }
                
                results.append(result)
                self.stats["total_processed"] += 1
                
                if prediction["label"] == "phishing":
                    self.stats["phishing_detected"] += 1
                else:
                    self.stats["benign_detected"] += 1
                
                # Save intermediate results every 100 certificates
                if len(results) % 100 == 0:
                    self._save_intermediate_results(results)
        
        return results
    
    def _save_intermediate_results(self, results: List[Dict]):
        """Save intermediate results to prevent data loss."""
        temp_file = Config.RESULTS_DIR / "predictions_temp.csv"
        df = pd.DataFrame(results)
        df.to_csv(temp_file, index=False)
    
    def save_results(self, results: List[Dict]):
        """Save final results to CSV."""
        df = pd.DataFrame(results)
        df.to_csv(Config.PREDICTIONS_CSV, index=False)
        
        self.logger.info(f"Results saved to {Config.PREDICTIONS_CSV}")
        self.logger.info(f"Total processed: {self.stats['total_processed']}")
        self.logger.info(f"Phishing detected: {self.stats['phishing_detected']}")
        self.logger.info(f"Benign detected: {self.stats['benign_detected']}")
        self.logger.info(f"Errors: {self.stats['errors']}")
        self.logger.info(f"API calls made: {self.stats['api_calls']}")
    
    def run(self, base_path: Path):
        """Main execution method."""
        cert_dirs = Config.get_cert_directories(base_path)
        
        all_results = []
        
        # Process phishing certificates
        if cert_dirs["phishing"].exists():
            phishing_results = self.process_certificates(cert_dirs["phishing"], "phishing")
            all_results.extend(phishing_results)
        else:
            self.logger.warning(f"Phishing directory not found: {cert_dirs['phishing']}")
        
        # Process benign certificates
        if cert_dirs["benign"].exists():
            benign_results = self.process_certificates(cert_dirs["benign"], "benign")
            all_results.extend(benign_results)
        else:
            self.logger.warning(f"Benign directory not found: {cert_dirs['benign']}")
        
        # Save all results
        if all_results:
            self.save_results(all_results)
        else:
            self.logger.error("No results to save!")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python main.py <certificates_directory>")
        print("Example: python main.py certificates/")
        sys.exit(1)
    
    base_path = Path(sys.argv[1])
    
    if not base_path.exists():
        print(f"Error: Directory not found: {base_path}")
        sys.exit(1)
    
    print("=" * 70)
    print("LLM-Based TLS Certificate Phishing Detection System")
    print("=" * 70)
    print()
    
    detector = CertificateDetector()
    
    try:
        detector.run(base_path)
        print("\n" + "=" * 70)
        print("Detection complete! Results saved to results/predictions.csv")
        print("Run 'python analysis.py results/' to analyze results")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Saving partial results...")
        # Results are auto-saved during processing
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()