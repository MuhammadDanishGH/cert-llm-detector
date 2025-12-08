#!/usr/bin/env python3
"""
Certificate Detector with Local LLM Support (Llama 3.1).
Optimized for reliable batch processing with robust error handling.
"""

import sys
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from tqdm import tqdm

from config import Config
from prompt_templates import PromptTemplates
from checkpoint_manager import CheckpointManager
from llm_client import LLMClientFactory, BaseLLMClient


class OptimizedCertificateDetector:
    """High-performance detector with local LLM support."""
    
    def __init__(self):
        """Initialize detector."""
        Config.validate()
        
        # Create LLM client (local or cloud)
        self.llm_client = LLMClientFactory.create_client(
            mode=Config.LLM_MODE,
            local_model=Config.LOCAL_MODEL,
            cloud_api_key=Config.GEMINI_API_KEY,
            cloud_model=Config.GEMINI_MODEL
        )
        
        self.checkpoint_mgr = CheckpointManager()
        
        self.stats = {
            "total_processed": len(self.checkpoint_mgr.processed_files),
            "phishing_detected": 0,
            "benign_detected": 0,
            "errors": 0,
            "api_calls": 0,
            "successful_api_calls": 0,
            "failed_api_calls": 0,
            "skipped_already_processed": 0,
            "start_time": time.time(),
            "batches_processed": 0,
            "salvaged_results": 0
        }
        
        self._print_startup_info()
    
    def _print_startup_info(self):
        """Print startup configuration."""
        perf = Config.get_performance_stats()
        print("="*70)
        print("🚀 CERTIFICATE DETECTOR WITH LOCAL LLM")
        print("="*70)
        print(f"LLM: {self.llm_client.get_name()}")
        print(f"Batch size: {Config.CERTS_PER_API_CALL} certs/request")
        print(f"Concurrent requests: {Config.MAX_CONCURRENT_REQUESTS}")
        print(f"Certificate truncate length: {Config.TRUNCATE_CERT_LENGTH} chars")
        print(f"Expected: ~{perf['certs_per_minute']:.0f} certs/min, ~{perf['certs_per_hour']:.0f} certs/hour")
        print(f"Est. time for 129K: ~{perf['estimated_time_for_129k_certs_hours']:.1f} hours")
        print(f"Est. time for 266K: ~{perf['estimated_time_for_266k_certs_hours']:.1f} hours")
        print(f"Already processed: {self.stats['total_processed']}")
        print(f"Save frequency: Every {Config.SAVE_EVERY_N_BATCHES} batches")
        print("="*70)
        print()
    
    def load_certificates_to_process(self, cert_dir: Path, true_label: str) -> List[Tuple[str, str, str]]:
        """Load unprocessed certificates."""
        all_certs = []
        cert_files = list(cert_dir.glob("*"))
        
        print(f"📂 Scanning {len(cert_files)} files...")
        
        for cert_path in cert_files:
            if self.checkpoint_mgr.is_processed(cert_path.name):
                self.stats["skipped_already_processed"] += 1
                continue
            
            try:
                size = cert_path.stat().st_size
                if size > Config.MAX_CERT_SIZE or size < Config.MIN_CERT_SIZE:
                    continue
                
                with open(cert_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if not content.strip():
                    continue
                
                content = PromptTemplates.truncate_certificate(content, Config.TRUNCATE_CERT_LENGTH)
                all_certs.append((cert_path.name, content, true_label))
                
            except Exception:
                continue
        
        return all_certs
    
    def process_batch(self, batch: List[Tuple[str, str, str]], batch_num: int) -> List[Dict]:
        """Process a batch using LLM client."""
        if not batch:
            return []
        
        cert_data = [(i, content) for i, (_, content, _) in enumerate(batch)]
        prompt = PromptTemplates.format_batch(cert_data)
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                # Small delay for rate limiting
                time.sleep(Config.REQUEST_DELAY_SECONDS)
                
                # Call LLM
                start_time = time.time()
                response_text = self.llm_client.generate(prompt)
                elapsed = time.time() - start_time
                
                self.stats["api_calls"] += 1
                self.stats["successful_api_calls"] += 1
                
                # Parse response
                results = self._parse_batch_response(response_text, batch)
                
                if results and len(results) == len(batch):
                    if attempt > 0:
                        print(f"✓ Batch {batch_num} succeeded on attempt {attempt + 1} ({elapsed:.1f}s)")
                    return results
                
                if results:
                    print(f"⚠️  Partial parse: {len(results)}/{len(batch)} (attempt {attempt + 1})")
                    # Accept partial results on last attempt
                    if attempt == Config.MAX_RETRIES - 1:
                        return results
                else:
                    print(f"⚠️  Parse failed for batch {batch_num} (attempt {attempt + 1})")
                
            except TimeoutError as e:
                self.stats["api_calls"] += 1
                self.stats["failed_api_calls"] += 1
                print(f"⏱️  Timeout in batch {batch_num} (attempt {attempt + 1}): {e}")
                
                if attempt < Config.MAX_RETRIES - 1:
                    wait_time = Config.RETRY_DELAY * (attempt + 1)
                    print(f"   Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
            
            except Exception as e:
                self.stats["api_calls"] += 1
                self.stats["failed_api_calls"] += 1
                
                print(f"❌ Error in batch {batch_num} (attempt {attempt + 1}): {type(e).__name__}")
                print(f"   {str(e)[:200]}")
                
                if attempt < Config.MAX_RETRIES - 1:
                    wait_time = Config.RETRY_DELAY * (attempt + 1)
                    print(f"   Retrying in {wait_time}s...")
                    time.sleep(wait_time)
        
        # Fallback after all retries
        print(f"❌ Batch {batch_num} failed after {Config.MAX_RETRIES} attempts - using fallback")
        self.stats["errors"] += len(batch)
        return self._create_fallback_results(batch)
    
    def _parse_batch_response(self, response_text: str, batch: List[Tuple]) -> List[Dict]:
        """Parse JSON array from response with robust error handling."""
        try:
            text = response_text.strip()
            
            # Extract JSON from markdown code blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            
            # Try to find JSON array in the text
            json_match = re.search(r'\[\s*\{.*\}\s*\]', text, re.DOTALL)
            if json_match:
                text = json_match.group(0)
            
            # Fix common JSON issues
            # Remove trailing commas before closing brackets
            text = re.sub(r',(\s*[\]}])', r'\1', text)
            
            # Parse JSON
            predictions = json.loads(text)
            
            if not isinstance(predictions, list):
                print(f"⚠️  Response is not a list: {type(predictions)}")
                return self._try_salvage_partial_json(response_text, batch)
            
            results = []
            for i, pred in enumerate(predictions):
                if i >= len(batch):
                    break
                
                filename, _, true_label = batch[i]
                
                # Handle both "label" and "predicted_label" keys
                label = pred.get("label") or pred.get("predicted_label", "benign")
                
                result = {
                    "filename": filename,
                    "true_label": true_label,
                    "predicted_label": str(label).lower().strip(),
                    "confidence": float(pred.get("confidence", 0.5)),
                    "reasoning": str(pred.get("reasoning", ""))[:500],  # Truncate long reasons
                    "red_flags": json.dumps(pred.get("red_flags", [])),
                    "timestamp": datetime.now().isoformat(),
                    "model": self.llm_client.get_name()
                }
                
                # Ensure label is valid
                if result["predicted_label"] not in ["phishing", "benign"]:
                    result["predicted_label"] = "benign"
                
                results.append(result)
                
                if result["predicted_label"] == "phishing":
                    self.stats["phishing_detected"] += 1
                else:
                    self.stats["benign_detected"] += 1
            
            return results
            
        except json.JSONDecodeError as e:
            print(f"⚠️  JSON decode error: {e}")
            print(f"   Attempting to salvage partial results...")
            
            # Try to salvage partial results
            salvaged = self._try_salvage_partial_json(response_text, batch)
            if salvaged:
                return salvaged
            
            return []
            
        except Exception as e:
            print(f"⚠️  Unexpected parse error: {type(e).__name__}: {e}")
            return []
    
    def _try_salvage_partial_json(self, response_text: str, batch: List[Tuple]) -> List[Dict]:
        """Try to extract individual JSON objects from malformed array."""
        results = []
        
        # Find all JSON objects that look like our format
        object_pattern = r'\{\s*"id"\s*:\s*(\d+).*?"label"\s*:\s*"(phishing|benign)".*?\}'
        matches = re.finditer(object_pattern, response_text, re.DOTALL)
        
        for match in matches:
            try:
                obj_text = match.group(0)
                # Fix trailing commas
                obj_text = re.sub(r',(\s*\})', r'\1', obj_text)
                pred = json.loads(obj_text)
                
                pred_id = int(pred.get("id", 0))
                if pred_id < len(batch):
                    filename, _, true_label = batch[pred_id]
                    
                    label = pred.get("label") or pred.get("predicted_label", "benign")
                    
                    result = {
                        "filename": filename,
                        "true_label": true_label,
                        "predicted_label": str(label).lower().strip(),
                        "confidence": float(pred.get("confidence", 0.5)),
                        "reasoning": str(pred.get("reasoning", ""))[:500],
                        "red_flags": json.dumps(pred.get("red_flags", [])),
                        "timestamp": datetime.now().isoformat(),
                        "model": self.llm_client.get_name()
                    }
                    
                    # Ensure label is valid
                    if result["predicted_label"] not in ["phishing", "benign"]:
                        result["predicted_label"] = "benign"
                    
                    results.append(result)
                    
                    if result["predicted_label"] == "phishing":
                        self.stats["phishing_detected"] += 1
                    else:
                        self.stats["benign_detected"] += 1
            except Exception:
                continue
        
        if results:
            self.stats["salvaged_results"] += len(results)
            print(f"✓ Salvaged {len(results)}/{len(batch)} results from malformed JSON")
        
        return results
    
    def _create_fallback_results(self, batch: List[Tuple]) -> List[Dict]:
        """Create fallback results for completely failed batches."""
        results = []
        for filename, _, true_label in batch:
            results.append({
                "filename": filename,
                "true_label": true_label,
                "predicted_label": "benign",
                "confidence": 0.0,
                "reasoning": "Error - fallback prediction (API/parsing failed)",
                "red_flags": json.dumps([]),
                "timestamp": datetime.now().isoformat(),
                "model": self.llm_client.get_name()
            })
            self.stats["benign_detected"] += 1
        return results
    
    def process_batch_parallel(self, batch_list: List[List[Tuple]], desc: str = "Processing") -> List[Dict]:
        """Process multiple batches in parallel (for local LLM)."""
        all_results = []
        
        with ThreadPoolExecutor(max_workers=Config.MAX_CONCURRENT_REQUESTS) as executor:
            futures = {
                executor.submit(self.process_batch, batch, i): i 
                for i, batch in enumerate(batch_list)
            }
            
            with tqdm(total=len(batch_list), desc=desc, unit="batch") as pbar:
                for future in as_completed(futures):
                    batch_num = futures[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                    except Exception as e:
                        print(f"❌ Exception in parallel batch {batch_num}: {e}")
                    finally:
                        pbar.update(1)
        
        return all_results
    
    def process_certificates(self, cert_dir: Path, true_label: str):
        """Process all certificates from a directory."""
        print(f"\n📁 Loading {true_label} certificates from {cert_dir.name}...")
        
        certs_to_process = self.load_certificates_to_process(cert_dir, true_label)
        
        if not certs_to_process:
            print(f"✓ All {true_label} certificates already processed!")
            return
        
        print(f"📊 {len(certs_to_process)} {true_label} certificates to process")
        print(f"📦 Will create {len(certs_to_process) // Config.CERTS_PER_API_CALL + 1} batches")
        print()
        
        # Create batches
        all_batches = [
            certs_to_process[i:i + Config.CERTS_PER_API_CALL]
            for i in range(0, len(certs_to_process), Config.CERTS_PER_API_CALL)
        ]
        
        batch_results = []
        
        # Process in chunks for periodic saving
        chunk_size = Config.SAVE_EVERY_N_BATCHES
        total_chunks = (len(all_batches) + chunk_size - 1) // chunk_size
        
        for chunk_idx in range(0, len(all_batches), chunk_size):
            chunk = all_batches[chunk_idx:chunk_idx + chunk_size]
            chunk_num = chunk_idx // chunk_size + 1
            
            print(f"\n{'='*70}")
            print(f"Processing chunk {chunk_num}/{total_chunks} ({len(chunk)} batches)")
            print(f"{'='*70}")
            
            # Process chunk (parallel if concurrent > 1)
            if Config.MAX_CONCURRENT_REQUESTS > 1:
                results = self.process_batch_parallel(
                    chunk, 
                    f"{true_label} chunk {chunk_num}/{total_chunks}"
                )
            else:
                results = []
                for batch_idx, batch in enumerate(chunk):
                    batch_num = chunk_idx + batch_idx
                    print(f"\nBatch {batch_num + 1}/{len(all_batches)} ({len(batch)} certs)")
                    batch_results_single = self.process_batch(batch, batch_num)
                    results.extend(batch_results_single)
            
            batch_results.extend(results)
            self.stats["total_processed"] += len(results)
            self.stats["batches_processed"] += len(chunk)
            
            # Save chunk
            if results:
                self._save_incremental_results(results)
                batch_results = []  # Clear after saving
    
    def _save_incremental_results(self, results: List[Dict]):
        """Save results incrementally."""
        if not results:
            return
        
        self.checkpoint_mgr.append_results(results)
        self.checkpoint_mgr.save_checkpoint(self.stats)
        
        elapsed = time.time() - self.stats["start_time"]
        rate = self.stats["total_processed"] / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"💾 CHECKPOINT SAVED")
        print(f"{'='*70}")
        print(f"Results saved: {len(results)}")
        print(f"Total processed: {self.stats['total_processed']}")
        print(f"Processing rate: {rate:.2f} certs/sec ({rate * 60:.0f} certs/min)")
        print(f"API calls: {self.stats['successful_api_calls']} success, {self.stats['failed_api_calls']} failed")
        print(f"Salvaged results: {self.stats['salvaged_results']}")
        print(f"Errors (fallback): {self.stats['errors']} certs")
        print(f"Model: {self.llm_client.get_name()}")
        print(f"Elapsed time: {elapsed / 60:.1f} minutes ({elapsed / 3600:.2f} hours)")
        
        # Estimate remaining time
        remaining = 129000 - self.stats["total_processed"]  # Approximate total
        if rate > 0:
            eta_seconds = remaining / rate
            eta_hours = eta_seconds / 3600
            print(f"Estimated time remaining: {eta_hours:.1f} hours")
        
        print(f"{'='*70}\n")
    
    def run(self, base_path: Path):
        """Main execution."""
        cert_dirs = Config.get_cert_directories(base_path)
        
        if cert_dirs["phishing"].exists():
            self.process_certificates(cert_dirs["phishing"], "phishing")
        else:
            print(f"⚠️  Phishing directory not found: {cert_dirs['phishing']}")
        
        if cert_dirs["benign"].exists():
            self.process_certificates(cert_dirs["benign"], "benign")
        else:
            print(f"⚠️  Benign directory not found: {cert_dirs['benign']}")
        
        self._print_summary()
    
    def _print_summary(self):
        """Print final summary."""
        elapsed = time.time() - self.stats["start_time"]
        
        print("\n" + "="*70)
        print("✅ PROCESSING COMPLETE")
        print("="*70)
        print(f"Model: {self.llm_client.get_name()}")
        print(f"Total processed: {self.stats['total_processed']}")
        print(f"  - Phishing detected: {self.stats['phishing_detected']}")
        print(f"  - Benign detected: {self.stats['benign_detected']}")
        print(f"Skipped (already done): {self.stats['skipped_already_processed']}")
        print(f"Batches processed: {self.stats['batches_processed']}")
        print(f"API calls: {self.stats['successful_api_calls']} success, {self.stats['failed_api_calls']} failed")
        print(f"Salvaged results: {self.stats['salvaged_results']}")
        print(f"Fallback predictions: {self.stats['errors']} certs")
        print(f"Processing time: {elapsed / 3600:.2f} hours ({elapsed / 60:.1f} minutes)")
        print(f"Average rate: {self.stats['total_processed'] / elapsed:.2f} certs/sec")
        print(f"\n📊 Results saved to: {Config.PREDICTIONS_CSV}")
        print(f"📈 Run 'python analysis.py results/' to analyze performance")
        print("="*70)


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python main.py certificates/")
        print("\nLLM Modes:")
        print("  export LLM_MODE=local   # Use local Ollama/Llama")
        print("  export LLM_MODE=cloud   # Use cloud Gemini")
        print("  export LLM_MODE=auto    # Try local, fallback to cloud")
        print("\nOptimization:")
        print("  export CERTS_PER_API_CALL=5         # Batch size")
        print("  export MAX_CONCURRENT_REQUESTS=2    # Parallel requests")
        print("  export TRUNCATE_CERT_LENGTH=1500    # Certificate truncation")
        sys.exit(1)
    
    base_path = Path(sys.argv[1])
    
    if not base_path.exists():
        print(f"❌ Error: Directory not found: {base_path}")
        sys.exit(1)
    
    try:
        detector = OptimizedCertificateDetector()
        detector.run(base_path)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        print("✓ Progress has been saved to checkpoints")
        print("✓ Run the same command again to resume from where you left off")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()