"""
Checkpoint management for resumable processing.
"""

import json
from pathlib import Path
from typing import Set, Dict, List
from config import Config
import pandas as pd


class CheckpointManager:
    """Manages progress checkpoints and resume capability."""
    
    def __init__(self):
        self.checkpoint_file = Config.CHECKPOINT_FILE
        self.processed_files_log = Config.PROCESSED_FILES_LOG
        self.predictions_csv = Config.PREDICTIONS_CSV
        
        # Load existing progress
        self.processed_files = self._load_processed_files()
        self.checkpoint_data = self._load_checkpoint()
    
    def _load_processed_files(self) -> Set[str]:
        """Load set of already processed filenames."""
        if not Config.AUTO_RESUME:
            return set()
        
        processed = set()
        
        # Load from processed files log
        if self.processed_files_log.exists():
            with open(self.processed_files_log, 'r') as f:
                processed.update(line.strip() for line in f if line.strip())
        
        # Also load from existing predictions CSV
        if self.predictions_csv.exists():
            try:
                df = pd.read_csv(self.predictions_csv)
                processed.update(df['filename'].tolist())
            except:
                pass
        
        if processed:
            print(f"📂 Found {len(processed)} already processed certificates")
            print(f"✓ Resume mode enabled - skipping processed files")
        
        return processed
    
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint data."""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def is_processed(self, filename: str) -> bool:
        """Check if a certificate has already been processed."""
        return filename in self.processed_files
    
    def mark_processed(self, filename: str):
        """Mark a certificate as processed."""
        self.processed_files.add(filename)
        
        # Append to log file (persistent)
        with open(self.processed_files_log, 'a') as f:
            f.write(f"{filename}\n")
    
    def save_checkpoint(self, stats: Dict):
        """Save checkpoint data."""
        if Config.ENABLE_CHECKPOINTS:
            checkpoint = {
                'timestamp': str(pd.Timestamp.now()),
                'stats': stats,
                'total_processed': len(self.processed_files)
            }
            
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
    
    def append_results(self, results: List[Dict]):
        """Append results to CSV incrementally."""
        
        
        df_new = pd.DataFrame(results)
        
        # Append to existing CSV or create new
        if self.predictions_csv.exists():
            df_new.to_csv(
                self.predictions_csv, 
                mode='a', 
                header=False, 
                index=False
            )
        else:
            df_new.to_csv(
                self.predictions_csv, 
                index=False
            )
        
        # Mark files as processed
        for result in results:
            self.mark_processed(result['filename'])