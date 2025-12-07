"""
Configuration module for LLM-based certificate phishing detection.
Handles API keys, rate limiting, and system parameters.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Configuration settings for the detection system."""
    
    # API Configuration
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = "gemini-1.5-flash"  # Fast and free tier available
    
    # Rate Limiting (Gemini Free Tier)
    MAX_REQUESTS_PER_MINUTE = 15
    REQUEST_DELAY_SECONDS = 4  # Conservative delay between requests
    
    # Batch Processing
    BATCH_SIZE = 100  # Process certificates in batches for better monitoring
    MAX_RETRIES = 3
    RETRY_DELAY = 5
    
    # Directory Structure
    RESULTS_DIR = Path("results")
    LOGS_DIR = RESULTS_DIR / "logs"
    ANALYSIS_DIR = RESULTS_DIR / "analysis"
    PLOTS_DIR = ANALYSIS_DIR / "plots"
    
    # Output Files
    PREDICTIONS_CSV = RESULTS_DIR / "predictions.csv"
    REPORT_FILE = ANALYSIS_DIR / "report.txt"
    
    # Certificate Processing
    MAX_CERT_SIZE = 10000  # Maximum certificate size in bytes to process
    
    @classmethod
    def validate(cls):
        """Validate configuration and create necessary directories."""
        if not cls.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY not found. Please set it in your environment:\n"
                "export GEMINI_API_KEY='your-api-key-here'"
            )
        
        # Create directory structure
        for directory in [cls.RESULTS_DIR, cls.LOGS_DIR, cls.ANALYSIS_DIR, cls.PLOTS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        return True
    
    @classmethod
    def get_cert_directories(cls, base_path: Path):
        """Get paths to phishing and benign certificate directories."""
        base = Path(base_path)
        return {
            "phishing": base / "phishing-certificates",
            "benign": base / "benign-certificates"
        }