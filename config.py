"""
Configuration optimized for local Llama 3.1.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Production-grade configuration."""
    
    # LLM Configuration
    LLM_MODE = os.getenv("LLM_MODE", "auto")
    
    # Local LLM (Ollama/Llama)
    LOCAL_MODEL = os.getenv("LOCAL_MODEL", "llama3.1:8b")
    LOCAL_HOST = os.getenv("LOCAL_HOST", "http://localhost:11434")
    
    # Cloud LLM (Gemini - fallback)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-exp")
    
    # Batch Processing - OPTIMIZED for local LLM
    # Smaller batches = more reliable, faster per-batch processing
    CERTS_PER_API_CALL = int(os.getenv("CERTS_PER_API_CALL", "5"))  # Reduced from 20!
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "2"))  # Reduced from 4
    
    # Rate Limiting
    REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "0.1"))  # Minimal for local
    
    # Checkpoint System
    CHECKPOINT_FREQUENCY = 100
    ENABLE_CHECKPOINTS = True
    AUTO_RESUME = True
    SAVE_EVERY_N_BATCHES = 10  # Save more frequently
    
    # Performance
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    MAX_CERT_SIZE = 5000
    MIN_CERT_SIZE = 50
    TRUNCATE_CERT_LENGTH = 1500  # Smaller = faster
    
    # Error logging
    DETAILED_ERROR_LOGGING = True
    SAVE_ERROR_DETAILS = True
    
    # Directory Structure
    RESULTS_DIR = Path("results")
    LOGS_DIR = RESULTS_DIR / "logs"
    ANALYSIS_DIR = RESULTS_DIR / "analysis"
    PLOTS_DIR = ANALYSIS_DIR / "plots"
    CHECKPOINTS_DIR = RESULTS_DIR / "checkpoints"
    ERRORS_DIR = RESULTS_DIR / "errors"
    
    # Output Files
    PREDICTIONS_CSV = RESULTS_DIR / "predictions.csv"
    CHECKPOINT_FILE = CHECKPOINTS_DIR / "progress.json"
    PROCESSED_FILES_LOG = CHECKPOINTS_DIR / "processed_files.txt"
    REPORT_FILE = ANALYSIS_DIR / "report.txt"
    ERROR_LOG_FILE = ERRORS_DIR / "error_log.jsonl"
    
    @classmethod
    def validate(cls):
        """Validate configuration."""
        for directory in [cls.RESULTS_DIR, cls.LOGS_DIR, cls.ANALYSIS_DIR, 
                         cls.PLOTS_DIR, cls.CHECKPOINTS_DIR, cls.ERRORS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        print(f"✓ LLM Mode: {cls.LLM_MODE}")
        
        if cls.LLM_MODE in ["local", "auto"]:
            print(f"  Local model: {cls.LOCAL_MODEL}")
            print(f"  Local host: {cls.LOCAL_HOST}")
            print(f"  Batch size: {cls.CERTS_PER_API_CALL} (optimized for local)")
        
        if cls.LLM_MODE in ["cloud", "auto"]:
            if cls.GEMINI_API_KEY:
                print(f"  Cloud model: {cls.GEMINI_MODEL}")
            elif cls.LLM_MODE == "cloud":
                raise ValueError("Cloud mode requires GEMINI_API_KEY")
        
        return True
    
    @classmethod
    def get_cert_directories(cls, base_path: Path):
        """Get certificate directories."""
        base = Path(base_path)
        return {
            "phishing": base / "phishing-certificates",
            "benign": base / "benign-certificates"
        }
    
    @classmethod
    def get_performance_stats(cls):
        """Calculate expected performance."""
        if cls.LLM_MODE == "local":
            # Local Llama 3.1 8B: ~5-15 seconds per batch of 5 certs
            # With 2 concurrent: ~10-30 certs per 10 seconds = ~60-180 certs/min
            certs_per_batch = cls.CERTS_PER_API_CALL
            concurrent = cls.MAX_CONCURRENT_REQUESTS
            seconds_per_batch = 10  # Conservative estimate
            
            certs_per_minute = (certs_per_batch * concurrent * 60) / seconds_per_batch
            certs_per_hour = certs_per_minute * 60
        else:
            certs_per_minute = (cls.CERTS_PER_API_CALL / cls.REQUEST_DELAY_SECONDS) * 60
            certs_per_hour = certs_per_minute * 60
        
        return {
            "certs_per_minute": certs_per_minute,
            "certs_per_hour": certs_per_hour,
            "estimated_time_for_129k_certs_hours": 129000 / certs_per_hour,
            "estimated_time_for_266k_certs_hours": 266000 / certs_per_hour
        }