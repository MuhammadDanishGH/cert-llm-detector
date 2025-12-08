#!/usr/bin/env python3
"""
Certificate Sampling Module
Generates representative subsets from the full dataset for efficient evaluation.
"""

import random
import shutil
from pathlib import Path
from typing import List
from config import Config


class CertificateSampler:
    """Handles sampling of certificate subsets."""
    
    def __init__(self, base_path: Path):
        """Initialize sampler with base path."""
        self.base_path = Path(base_path)
        cert_dirs = Config.get_cert_directories(self.base_path)
        self.phishing_dir = cert_dirs["phishing_raw"]
        self.benign_dir = cert_dirs["benign_raw"]
        
        # Output directories
        self.subset_base = self.base_path / "selected-subset"
        self.phishing_subset_dir = self.subset_base / "phishing-certificates"
        self.benign_subset_dir = self.subset_base / "benign-certificates"
    
    def get_valid_certificates(self, cert_dir: Path) -> List[Path]:
        """Get list of valid certificate files from a directory."""
        valid_certs = []
        
        if not cert_dir.exists():
            print(f"⚠️  Directory not found: {cert_dir}")
            return []
        
        for cert_file in cert_dir.glob("*"):
            if not cert_file.is_file():
                continue
            
            try:
                size = cert_file.stat().st_size
                if size < Config.MIN_CERT_SIZE or size > Config.MAX_CERT_SIZE:
                    continue
                
                # Quick validation - check if file is readable
                with open(cert_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if not content.strip():
                        continue
                
                valid_certs.append(cert_file)
                
            except Exception:
                continue
        
        return valid_certs
    
    def sample_certificates(self, cert_files: List[Path], sample_size: int, method: str = "random") -> List[Path]:
        """Sample certificates using the specified method."""
        if len(cert_files) <= sample_size:
            print(f"  ℹ️  Available files ({len(cert_files)}) <= sample size ({sample_size}), using all")
            return cert_files
        
        if method == "random":
            # Random sampling with seed for reproducibility
            random.seed(Config.RANDOM_SEED)
            sampled = random.sample(cert_files, sample_size)
            
        elif method == "first":
            # Take first N files (simple, deterministic)
            sampled = cert_files[:sample_size]
            
        elif method == "stratified":
            # Stratified sampling (distribute across the dataset)
            step = len(cert_files) / sample_size
            indices = [int(i * step) for i in range(sample_size)]
            sampled = [cert_files[i] for i in indices]
            
        else:
            raise ValueError(f"Unknown sampling method: {method}")
        
        return sampled
    
    def create_subset(self, source_dir: Path, target_dir: Path, label: str) -> int:
        """Create subset for a specific label (phishing/benign)."""
        print(f"\n{'='*70}")
        print(f"📊 Creating {label} subset")
        print(f"{'='*70}")
        print(f"Source: {source_dir}")
        print(f"Target: {target_dir}")
        print(f"Sample size: {Config.SAMPLE_SIZE_PER_CLASS}")
        print(f"Method: {Config.SAMPLING_METHOD}")
        print(f"Random seed: {Config.RANDOM_SEED}")
        
        # Get valid certificates
        print(f"\n🔍 Scanning {label} certificates...")
        valid_certs = self.get_valid_certificates(source_dir)
        print(f"✓ Found {len(valid_certs)} valid certificates")
        
        if not valid_certs:
            print(f"❌ No valid certificates found in {source_dir}")
            return 0
        
        # Sample
        print(f"\n🎲 Sampling {Config.SAMPLE_SIZE_PER_CLASS} certificates...")
        sampled_certs = self.sample_certificates(
            valid_certs, 
            Config.SAMPLE_SIZE_PER_CLASS,
            Config.SAMPLING_METHOD
        )
        print(f"✓ Selected {len(sampled_certs)} certificates")
        
        # Create target directory
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy files
        print(f"\n📁 Copying files to {target_dir}...")
        copied = 0
        for cert_file in sampled_certs:
            try:
                target_file = target_dir / cert_file.name
                shutil.copy2(cert_file, target_file)
                copied += 1
            except Exception as e:
                print(f"⚠️  Failed to copy {cert_file.name}: {e}")
        
        print(f"✓ Copied {copied} certificates")
        return copied
    
    def generate_subsets(self, force: bool = False) -> bool:
        """Generate subsets for both phishing and benign certificates."""
        print("\n" + "="*70)
        print("🎯 CERTIFICATE SUBSET GENERATION")
        print("="*70)
        print(f"Sampling enabled: {Config.ENABLE_SAMPLING}")
        print(f"Sample size per class: {Config.SAMPLE_SIZE_PER_CLASS}")
        print(f"Sampling method: {Config.SAMPLING_METHOD}")
        print(f"Random seed: {Config.RANDOM_SEED}")
        
        # Check if subsets already exist
        if not force:
            phishing_exists = self.phishing_subset_dir.exists() and list(self.phishing_subset_dir.glob("*"))
            benign_exists = self.benign_subset_dir.exists() and list(self.benign_subset_dir.glob("*"))
            
            if phishing_exists and benign_exists:
                phishing_count = len(list(self.phishing_subset_dir.glob("*")))
                benign_count = len(list(self.benign_subset_dir.glob("*")))
                print("\n✓ Subsets already exist:")
                print(f"  - Phishing: {phishing_count} certificates")
                print(f"  - Benign: {benign_count} certificates")
                print("\nℹ️  To regenerate, delete the subset directory or use --force")
                return True
        
        # Clear existing subsets if force mode
        if force and self.subset_base.exists():
            print("\n🗑️  Removing existing subsets...")
            shutil.rmtree(self.subset_base)
        
        # Create subsets
        phishing_count = self.create_subset(
            self.phishing_dir,
            self.phishing_subset_dir,
            "phishing"
        )
        
        benign_count = self.create_subset(
            self.benign_dir,
            self.benign_subset_dir,
            "benign"
        )
        
        # Summary
        print("\n" + "="*70)
        print("✅ SUBSET GENERATION COMPLETE")
        print("="*70)
        print(f"Phishing certificates: {phishing_count}")
        print(f"Benign certificates: {benign_count}")
        print(f"Total subset size: {phishing_count + benign_count}")
        print(f"\n📁 Subsets saved to: {self.subset_base}")
        print("="*70)
        
        return phishing_count > 0 and benign_count > 0


def main():
    """Main entry point for standalone sampling."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate certificate subsets for evaluation")
    parser.add_argument("base_path", help="Base path containing certificate directories")
    parser.add_argument("--force", action="store_true", help="Force regeneration of subsets")
    
    args = parser.parse_args()
    
    base_path = Path(args.base_path)
    if not base_path.exists():
        print(f"❌ Error: Directory not found: {base_path}")
        sys.exit(1)
    
    # Validate config
    Config.validate()
    
    if not Config.ENABLE_SAMPLING and not args.force:
        print("⚠️  Sampling is disabled in configuration (ENABLE_SAMPLING=false)")
        print("   Set ENABLE_SAMPLING=true in .env or use --force flag")
        sys.exit(1)
    
    # Generate subsets
    sampler = CertificateSampler(base_path)
    success = sampler.generate_subsets(force=args.force)
    
    if success:
        print("\n✅ Subset generation successful!")
        print("You can now run: python main.py certificates/")
    else:
        print("\n❌ Subset generation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
