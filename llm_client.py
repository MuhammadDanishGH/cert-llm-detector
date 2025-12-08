"""
Unified LLM client with robust error handling.
"""

import json
import time
import re
from typing import Dict, List, Optional, Literal
from abc import ABC, abstractmethod

import requests
from config import Config


class BaseLLMClient(ABC):
    """Base class for LLM clients."""
    
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate response from prompt."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get model name."""
        pass


class OllamaClient(BaseLLMClient):
    """Local Ollama/Llama client with robust handling."""
    
    def __init__(self, model_name: str = "llama3.1:8b", host: str = "http://localhost:11434"):
        self.model_name = model_name
        self.host = host
        self.endpoint = f"{host}/api/generate"
        
        # Test connection
        self._test_connection()
        
        print(f"✓ Ollama client initialized: {model_name}")
    
    def _test_connection(self):
        """Test if Ollama is running."""
        try:
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            if response.status_code != 200:
                raise ConnectionError("Ollama not responding")
        except Exception as e:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self.host}\n"
                f"Make sure Ollama is running: 'ollama serve'\n"
                f"Error: {e}"
            )
    
    def generate(self, prompt: str) -> str:
        """Generate response using Ollama with increased timeout."""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 2048,  # Increased for batch responses
                "num_ctx": 4096,      # Context window
            }
        }
        
        try:
            # Much longer timeout for batch processing
            timeout = 300  # 5 minutes max per batch
            
            response = requests.post(self.endpoint, json=payload, timeout=timeout)
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "")
            
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Ollama request timed out (>{timeout}s) for model {self.model_name}")
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed: {e}")
    
    def get_name(self) -> str:
        return f"Ollama:{self.model_name}"


class GeminiClient(BaseLLMClient):
    """Cloud Gemini client (fallback)."""
    
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash-exp"):
        import google.generativeai as genai
        
        self.model_name = model_name
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        
        print(f"✓ Gemini client initialized: {model_name}")
    
    def generate(self, prompt: str) -> str:
        """Generate response using Gemini."""
        response = self.model.generate_content(prompt)
        return response.text
    
    def get_name(self) -> str:
        return f"Gemini:{self.model_name}"


class LLMClientFactory:
    """Factory to create appropriate LLM client."""
    
    @staticmethod
    def create_client(
        mode: Literal["local", "cloud", "auto"] = "auto",
        local_model: str = "llama3.1:8b",
        cloud_api_key: Optional[str] = None,
        cloud_model: str = "gemini-2.0-flash-exp"
    ) -> BaseLLMClient:
        """Create LLM client based on mode."""
        
        if mode == "local":
            return OllamaClient(model_name=local_model)
        
        elif mode == "cloud":
            if not cloud_api_key:
                raise ValueError("Cloud mode requires API key")
            return GeminiClient(api_key=cloud_api_key, model_name=cloud_model)
        
        elif mode == "auto":
            try:
                return OllamaClient(model_name=local_model)
            except ConnectionError as e:
                print(f"⚠️  Local LLM not available: {e}")
                print(f"🔄 Falling back to cloud (Gemini)...")
                
                if not cloud_api_key:
                    raise ValueError("Fallback to cloud requires API key")
                
                return GeminiClient(api_key=cloud_api_key, model_name=cloud_model)
        
        else:
            raise ValueError(f"Invalid mode: {mode}")