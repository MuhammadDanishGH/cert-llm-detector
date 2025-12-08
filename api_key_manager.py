"""
API key manager with detailed error tracking.
"""

import time
import json
from typing import Optional, Dict
import google.generativeai as genai
from config import Config
from datetime import datetime


class APIKeyManager:
    """Manages API keys with detailed error tracking."""
    
    def __init__(self):
        self.keys = Config.GEMINI_API_KEYS
        self.current_key_index = 0
        self.consecutive_rate_limits = 0
        self.current_delay = Config.BASE_REQUEST_DELAY
        
        # Error tracking
        self.error_history = []
        self.last_error_type = None
        self.successful_requests = 0
        
        if not self.keys:
            raise ValueError("No API keys configured!")
        
        self._switch_to_key(0)
        print(f"🔑 API Key Manager: {len(self.keys)} key(s) loaded")
        print(f"⏱️  Starting delay: {self.current_delay}s")
    
    def _switch_to_key(self, index: int):
        """Switch to a specific API key."""
        if 0 <= index < len(self.keys):
            self.current_key_index = index
            genai.configure(api_key=self.keys[index])
    
    def get_current_key_info(self) -> str:
        """Get info about current key."""
        return f"Key #{self.current_key_index + 1}/{len(self.keys)} | Delay: {self.current_delay:.1f}s"
    
    def get_current_delay(self) -> float:
        """Get current delay."""
        return self.current_delay
    
    def log_error(self, error: Exception, context: Dict = None):
        """Log detailed error information."""
        error_entry = {
            "timestamp": datetime.now().isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "current_delay": self.current_delay,
            "consecutive_limits": self.consecutive_rate_limits,
            "successful_requests": self.successful_requests,
            "context": context or {}
        }
        
        self.error_history.append(error_entry)
        self.last_error_type = type(error).__name__
        
        # Save to file
        if Config.SAVE_ERROR_DETAILS:
            with open(Config.ERROR_LOG_FILE, 'a') as f:
                f.write(json.dumps(error_entry) + '\n')
        
        return error_entry
    
    def categorize_error(self, error: Exception) -> str:
        """Categorize the error type."""
        error_str = str(error).lower()
        
        if "429" in error_str or "quota" in error_str:
            return "RATE_LIMIT"
        elif "400" in error_str or "invalid" in error_str:
            return "INVALID_REQUEST"
        elif "401" in error_str or "unauthorized" in error_str or "api key" in error_str:
            return "AUTH_ERROR"
        elif "500" in error_str or "internal" in error_str:
            return "SERVER_ERROR"
        elif "timeout" in error_str:
            return "TIMEOUT"
        elif "resource" in error_str and "exhausted" in error_str:
            return "RESOURCE_EXHAUSTED"
        else:
            return "UNKNOWN"
    
    def handle_error(self, error: Exception, context: Dict = None) -> Dict:
        """Handle error with appropriate response."""
        error_entry = self.log_error(error, context)
        error_category = self.categorize_error(error)
        
        print(f"\n❌ ERROR DETECTED: {error_category}")
        print(f"   Message: {str(error)[:200]}")
        
        if error_category == "RATE_LIMIT":
            self.consecutive_rate_limits += 1
            
            if self.consecutive_rate_limits >= Config.CONSECUTIVE_LIMITS_THRESHOLD:
                print(f"⚠️  Hit {self.consecutive_rate_limits} consecutive rate limits!")
                print(f"   Taking LONG pause: {Config.LONG_PAUSE_DURATION}s")
                time.sleep(Config.LONG_PAUSE_DURATION)
                self.consecutive_rate_limits = 0
                self.current_delay = Config.BASE_REQUEST_DELAY
            else:
                # Increase delay
                old_delay = self.current_delay
                self.current_delay = min(
                    self.current_delay * Config.DELAY_INCREASE_FACTOR,
                    Config.MAX_REQUEST_DELAY
                )
                print(f"⏸️  Rate limited. Delay: {old_delay:.1f}s → {self.current_delay:.1f}s")
                time.sleep(Config.RATE_LIMIT_PAUSE)
        
        elif error_category == "RESOURCE_EXHAUSTED":
            print(f"⏸️  Resource exhausted. Taking long pause: {Config.LONG_PAUSE_DURATION}s")
            time.sleep(Config.LONG_PAUSE_DURATION)
            self.current_delay = Config.BASE_REQUEST_DELAY
        
        elif error_category == "AUTH_ERROR":
            print(f"🔑 Authentication error! Check your API key.")
            raise error
        
        elif error_category in ["SERVER_ERROR", "TIMEOUT"]:
            print(f"🔄 {error_category} - will retry with backoff")
            time.sleep(Config.RETRY_DELAY)
        
        else:
            print(f"⚠️  Unknown error - will retry")
            time.sleep(Config.RETRY_DELAY)
        
        return {
            "category": error_category,
            "should_retry": error_category not in ["AUTH_ERROR", "INVALID_REQUEST"]
        }
    
    def mark_success(self):
        """Mark successful request."""
        self.successful_requests += 1
        
        if self.consecutive_rate_limits > 0:
            self.consecutive_rate_limits = 0
        
        # Gradually reduce delay on success
        if self.successful_requests % 10 == 0:  # Every 10 successful requests
            old_delay = self.current_delay
            self.current_delay = max(
                self.current_delay * Config.DELAY_DECREASE_FACTOR,
                Config.MIN_REQUEST_DELAY
            )
            if old_delay != self.current_delay:
                print(f"✅ Performance good! Delay: {old_delay:.1f}s → {self.current_delay:.1f}s")
    
    def get_error_summary(self) -> Dict:
        """Get summary of errors."""
        if not self.error_history:
            return {"total_errors": 0}
        
        error_types = {}
        for entry in self.error_history:
            error_type = entry["error_type"]
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            "total_errors": len(self.error_history),
            "error_types": error_types,
            "last_error": self.error_history[-1] if self.error_history else None
        }