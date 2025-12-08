#!/usr/bin/env python3
"""
Analysis module - same as before with minor enhancements.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, accuracy_score, precision_score, 
    recall_score, f1_score, classification_report
)

from config import Config


class ResultsAnalyzer:
    """Analyze detection results."""
    
    def __init__(self, results_dir: Path):
        self.results_dir = Path(results_dir)
        self.predictions_file = self.results_dir / "predictions.csv"
        
        if not self.predictions_file.exists():
            raise FileNotFoundError(
                f"Predictions file not found: {self.predictions_file}\n"
                f"Run main.py first to generate results."
            )
        
        self.df = pd.read_csv(self.predictions_file)
        
        # Remove duplicates (in case of resume issues)
        initial_len = len(self.df)
        self.df = self.df.drop_duplicates(subset=['filename'], keep='last')
        if len(self.df) < initial_len:
            print(f"ℹ️  Removed {initial_len - len(self.df)} duplicate entries")
        
        Config.ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
        Config.PLOTS_DIR.mkdir(parents=True, exist_ok=True)
        
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
        
        print(f"📊 Loaded {len(self.df)} predictions for analysis")
    
    def compute_metrics(self) -> Dict:
        """Compute classification metrics."""
        y_true = self.df['true_label']
        y_pred = self.df['predicted_label']
        
        y_true_bin = (y_true == 'phishing').astype(int)
        y_pred_bin = (y_pred == 'phishing').astype(int)
        
        metrics = {
            'accuracy': accuracy_score(y_true_bin, y_pred_bin),
            'precision': precision_score(y_true_bin, y_pred_bin, zero_division=0),
            'recall': recall_score(y_true_bin, y_pred_bin, zero_division=0),
            'f1': f1_score(y_true_bin, y_pred_bin, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true_bin, y_pred_bin),
            'classification_report': classification_report(
                y_true_bin, y_pred_bin, target_names=['Benign', 'Phishing']
            )
        }
        
        return metrics
    
    def plot_confusion_matrix(self, cm, save_path: Path):
        """Plot confusion matrix."""
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Phishing'],
            yticklabels=['Benign', 'Phishing']
        )
        plt.title('Confusion Matrix', fontsize=16, pad=20)
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_confidence_distribution(self, save_path: Path):
        """Plot confidence distributions."""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Overall
        axes[0, 0].hist(self.df['confidence'], bins=50, edgecolor='black', alpha=0.7)
        axes[0, 0].set_title('Overall Confidence Distribution')
        axes[0, 0].set_xlabel('Confidence')
        axes[0, 0].set_ylabel('Frequency')
        
        # By true label
        for label in ['phishing', 'benign']:
            data = self.df[self.df['true_label'] == label]['confidence']
            axes[0, 1].hist(data, bins=30, alpha=0.6, label=label.capitalize())
        axes[0, 1].set_title('Confidence by True Label')
        axes[0, 1].legend()
        
        # By correctness
        self.df['correct'] = self.df['true_label'] == self.df['predicted_label']
        for correct in [True, False]:
            data = self.df[self.df['correct'] == correct]['confidence']
            label = 'Correct' if correct else 'Incorrect'
            axes[1, 0].hist(data, bins=30, alpha=0.6, label=label)
        axes[1, 0].set_title('Confidence by Correctness')
        axes[1, 0].legend()
        
        # Box plot
        self.df['outcome'] = self.df.apply(
            lambda row: f"{'✓' if row['correct'] else '✗'} {row['predicted_label']}", axis=1
        )
        sns.boxplot(data=self.df, x='outcome', y='confidence', ax=axes[1, 1])
        axes[1, 1].set_title('Confidence by Outcome')
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def analyze_red_flags(self) -> Dict:
        """Analyze red flags."""
        all_flags = []
        for flags_str in self.df['red_flags']:
            try:
                flags = json.loads(flags_str)
                if isinstance(flags, list):
                    all_flags.extend(flags)
            except:
                continue
        
        flag_counts = Counter(all_flags)
        return {
            'total_flags': len(all_flags),
            'unique_flags': len(flag_counts),
            'top_flags': flag_counts.most_common(20)
        }
    
    def generate_report(self, metrics: Dict, flag_data: Dict) -> str:
        """Generate text report."""
        report = []
        report.append("=" * 80)
        report.append("LLM-BASED CERTIFICATE PHISHING DETECTION - ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        report.append("DATASET STATISTICS")
        report.append("-" * 80)
        report.append(f"Total certificates: {len(self.df)}")
        report.append(f"True phishing: {(self.df['true_label'] == 'phishing').sum()}")
        report.append(f"True benign: {(self.df['true_label'] == 'benign').sum()}")
        report.append("")
        
        report.append("PERFORMANCE METRICS")
        report.append("-" * 80)
        report.append(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        report.append(f"Precision: {metrics['precision']:.4f}")
        report.append(f"Recall:    {metrics['recall']:.4f}")
        report.append(f"F1-Score:  {metrics['f1']:.4f}")
        report.append("")
        
        cm = metrics['confusion_matrix']
        report.append("CONFUSION MATRIX")
        report.append("-" * 80)
        report.append(f"True Negatives:  {cm[0, 0]}")
        report.append(f"False Positives: {cm[0, 1]}")
        report.append(f"False Negatives: {cm[1, 0]}")
        report.append(f"True Positives:  {cm[1, 1]}")
        report.append("")
        
        report.append("CONFIDENCE STATISTICS")
        report.append("-" * 80)
        report.append(f"Mean: {self.df['confidence'].mean():.4f}")
        report.append(f"Median: {self.df['confidence'].median():.4f}")
        report.append(f"Std: {self.df['confidence'].std():.4f}")
        report.append("")
        
        report.append("TOP RED FLAGS")
        report.append("-" * 80)
        for i, (flag, count) in enumerate(flag_data['top_flags'][:15], 1):
            report.append(f"{i}. {flag}: {count}")
        
        report.append("")
        report.append("=" * 80)
        return "\n".join(report)
    
    def run_analysis(self):
        """Run full analysis."""
        print("Computing metrics...")
        metrics = self.compute_metrics()
        
        print("Analyzing red flags...")
        flag_data = self.analyze_red_flags()
        
        print("Generating visualizations...")
        self.plot_confusion_matrix(metrics['confusion_matrix'], Config.PLOTS_DIR / 'confusion_matrix.png')
        self.plot_confidence_distribution(Config.PLOTS_DIR / 'confidence_distribution.png')
        
        print("Generating report...")
        report = self.generate_report(metrics, flag_data)
        
        with open(Config.REPORT_FILE, 'w') as f:
            f.write(report)
        
        print(report)
        print(f"\n✅ Analysis complete!")
        print(f"📄 Report: {Config.REPORT_FILE}")
        print(f"📊 Plots: {Config.PLOTS_DIR}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python analysis.py results/")
        sys.exit(1)
    
    results_dir = Path(sys.argv[1])
    
    try:
        analyzer = ResultsAnalyzer(results_dir)
        analyzer.run_analysis()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()