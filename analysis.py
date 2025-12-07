#!/usr/bin/env python3
"""
Analysis module for LLM-based certificate phishing detection results.
Computes metrics, generates visualizations, and produces comprehensive reports.
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
    confusion_matrix, 
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    classification_report
)

from config import Config


class ResultsAnalyzer:
    """Analyze detection results and generate comprehensive reports."""
    
    def __init__(self, results_dir: Path):
        """Initialize analyzer with results directory."""
        self.results_dir = Path(results_dir)
        self.predictions_file = self.results_dir / "predictions.csv"
        
        if not self.predictions_file.exists():
            raise FileNotFoundError(f"Predictions file not found: {self.predictions_file}")
        
        # Load data
        self.df = pd.read_csv(self.predictions_file)
        
        # Ensure output directories exist
        Config.ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
        Config.PLOTS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Configure plotting
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
    
    def compute_metrics(self) -> Dict:
        """Compute classification metrics."""
        y_true = self.df['true_label']
        y_pred = self.df['predicted_label']
        
        # Convert to binary (1 = phishing, 0 = benign)
        y_true_bin = (y_true == 'phishing').astype(int)
        y_pred_bin = (y_pred == 'phishing').astype(int)
        
        metrics = {
            'accuracy': accuracy_score(y_true_bin, y_pred_bin),
            'precision': precision_score(y_true_bin, y_pred_bin, zero_division=0),
            'recall': recall_score(y_true_bin, y_pred_bin, zero_division=0),
            'f1': f1_score(y_true_bin, y_pred_bin, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true_bin, y_pred_bin),
            'classification_report': classification_report(
                y_true_bin, 
                y_pred_bin, 
                target_names=['Benign', 'Phishing']
            )
        }
        
        return metrics
    
    def plot_confusion_matrix(self, cm, save_path: Path):
        """Plot confusion matrix heatmap."""
        plt.figure(figsize=(10, 8))
        
        sns.heatmap(
            cm, 
            annot=True, 
            fmt='d', 
            cmap='Blues',
            xticklabels=['Benign', 'Phishing'],
            yticklabels=['Benign', 'Phishing'],
            cbar_kws={'label': 'Count'}
        )
        
        plt.title('Confusion Matrix: LLM-Based Certificate Detection', fontsize=16, pad=20)
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_confidence_distribution(self, save_path: Path):
        """Plot confidence score distributions."""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Overall confidence distribution
        axes[0, 0].hist(self.df['confidence'], bins=50, edgecolor='black', alpha=0.7)
        axes[0, 0].set_title('Overall Confidence Distribution')
        axes[0, 0].set_xlabel('Confidence Score')
        axes[0, 0].set_ylabel('Frequency')
        axes[0, 0].axvline(self.df['confidence'].mean(), color='red', 
                           linestyle='--', label=f'Mean: {self.df["confidence"].mean():.3f}')
        axes[0, 0].legend()
        
        # Confidence by true label
        for label in ['phishing', 'benign']:
            data = self.df[self.df['true_label'] == label]['confidence']
            axes[0, 1].hist(data, bins=30, alpha=0.6, label=label.capitalize(), edgecolor='black')
        axes[0, 1].set_title('Confidence by True Label')
        axes[0, 1].set_xlabel('Confidence Score')
        axes[0, 1].set_ylabel('Frequency')
        axes[0, 1].legend()
        
        # Confidence by prediction correctness
        self.df['correct'] = self.df['true_label'] == self.df['predicted_label']
        for correct in [True, False]:
            data = self.df[self.df['correct'] == correct]['confidence']
            label = 'Correct' if correct else 'Incorrect'
            axes[1, 0].hist(data, bins=30, alpha=0.6, label=label, edgecolor='black')
        axes[1, 0].set_title('Confidence by Prediction Correctness')
        axes[1, 0].set_xlabel('Confidence Score')
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].legend()
        
        # Box plot: confidence by prediction outcome
        self.df['outcome'] = self.df.apply(
            lambda row: f"{'Correct' if row['correct'] else 'Wrong'} {row['predicted_label'].capitalize()}", 
            axis=1
        )
        sns.boxplot(data=self.df, x='outcome', y='confidence', ax=axes[1, 1])
        axes[1, 1].set_title('Confidence by Prediction Outcome')
        axes[1, 1].set_xlabel('Outcome')
        axes[1, 1].set_ylabel('Confidence Score')
        axes[1, 1].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def analyze_red_flags(self) -> Dict:
        """Analyze red flags identified by LLM."""
        all_flags = []
        
        for flags_str in self.df['red_flags']:
            try:
                flags = json.loads(flags_str)
                if isinstance(flags, list):
                    all_flags.extend(flags)
            except (json.JSONDecodeError, TypeError):
                continue
        
        flag_counts = Counter(all_flags)
        
        return {
            'total_flags': len(all_flags),
            'unique_flags': len(flag_counts),
            'top_flags': flag_counts.most_common(20)
        }
    
    def plot_red_flags(self, flag_data: Dict, save_path: Path):
        """Plot most common red flags."""
        if not flag_data['top_flags']:
            return
        
        flags, counts = zip(*flag_data['top_flags'][:15])
        
        plt.figure(figsize=(12, 8))
        plt.barh(range(len(flags)), counts, color='coral', edgecolor='black')
        plt.yticks(range(len(flags)), flags)
        plt.xlabel('Frequency', fontsize=12)
        plt.title('Top 15 Red Flags Identified by LLM', fontsize=14, pad=20)
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    def get_misclassification_examples(self, n: int = 10) -> Dict[str, List]:
        """Get examples of misclassified certificates."""
        incorrect = self.df[self.df['true_label'] != self.df['predicted_label']]
        
        # False positives (benign predicted as phishing)
        false_positives = incorrect[incorrect['true_label'] == 'benign'].nlargest(n, 'confidence')
        
        # False negatives (phishing predicted as benign)
        false_negatives = incorrect[incorrect['true_label'] == 'phishing'].nlargest(n, 'confidence')
        
        return {
            'false_positives': false_positives[['filename', 'confidence', 'reasoning']].to_dict('records'),
            'false_negatives': false_negatives[['filename', 'confidence', 'reasoning']].to_dict('records')
        }
    
    def generate_report(self, metrics: Dict, flag_data: Dict, examples: Dict) -> str:
        """Generate comprehensive text report."""
        report = []
        report.append("=" * 80)
        report.append("LLM-BASED TLS CERTIFICATE PHISHING DETECTION - ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Dataset statistics
        report.append("DATASET STATISTICS")
        report.append("-" * 80)
        report.append(f"Total certificates analyzed: {len(self.df)}")
        report.append(f"True phishing certificates: {(self.df['true_label'] == 'phishing').sum()}")
        report.append(f"True benign certificates: {(self.df['true_label'] == 'benign').sum()}")
        report.append("")
        
        # Performance metrics
        report.append("CLASSIFICATION PERFORMANCE")
        report.append("-" * 80)
        report.append(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        report.append(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        report.append(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        report.append(f"F1-Score:  {metrics['f1']:.4f}")
        report.append("")
        
        # Confusion matrix
        cm = metrics['confusion_matrix']
        report.append("CONFUSION MATRIX")
        report.append("-" * 80)
        report.append(f"True Negatives (Correct Benign):  {cm[0, 0]}")
        report.append(f"False Positives (Benign as Phishing): {cm[0, 1]}")
        report.append(f"False Negatives (Phishing as Benign): {cm[1, 0]}")
        report.append(f"True Positives (Correct Phishing): {cm[1, 1]}")
        report.append("")
        
        # Detailed classification report
        report.append("DETAILED CLASSIFICATION REPORT")
        report.append("-" * 80)
        report.append(metrics['classification_report'])
        report.append("")
        
        # Confidence statistics
        report.append("CONFIDENCE SCORE STATISTICS")
        report.append("-" * 80)
        report.append(f"Mean confidence: {self.df['confidence'].mean():.4f}")
        report.append(f"Median confidence: {self.df['confidence'].median():.4f}")
        report.append(f"Std deviation: {self.df['confidence'].std():.4f}")
        report.append(f"Min confidence: {self.df['confidence'].min():.4f}")
        report.append(f"Max confidence: {self.df['confidence'].max():.4f}")
        report.append("")
        
        # Red flags analysis
        report.append("RED FLAGS ANALYSIS")
        report.append("-" * 80)
        report.append(f"Total red flags identified: {flag_data['total_flags']}")
        report.append(f"Unique red flag types: {flag_data['unique_flags']}")
        report.append("")
        report.append("Top 10 Most Common Red Flags:")
        for i, (flag, count) in enumerate(flag_data['top_flags'][:10], 1):
            report.append(f"  {i}. {flag}: {count} occurrences")
        report.append("")
        
        # Misclassification examples
        report.append("MISCLASSIFICATION EXAMPLES")
        report.append("-" * 80)
        report.append("")
        report.append("FALSE POSITIVES (Benign predicted as Phishing):")
        for i, ex in enumerate(examples['false_positives'][:5], 1):
            report.append(f"\n  {i}. {ex['filename']}")
            report.append(f"     Confidence: {ex['confidence']:.4f}")
            report.append(f"     Reasoning: {ex['reasoning'][:200]}...")
        
        report.append("")
        report.append("")
        report.append("FALSE NEGATIVES (Phishing predicted as Benign):")
        for i, ex in enumerate(examples['false_negatives'][:5], 1):
            report.append(f"\n  {i}. {ex['filename']}")
            report.append(f"     Confidence: {ex['confidence']:.4f}")
            report.append(f"     Reasoning: {ex['reasoning'][:200]}...")
        
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def run_analysis(self):
        """Execute full analysis pipeline."""
        print("Computing classification metrics...")
        metrics = self.compute_metrics()
        
        print("Analyzing red flags...")
        flag_data = self.analyze_red_flags()
        
        print("Extracting misclassification examples...")
        examples = self.get_misclassification_examples()
        
        print("Generating visualizations...")
        self.plot_confusion_matrix(
            metrics['confusion_matrix'], 
            Config.PLOTS_DIR / 'confusion_matrix.png'
        )
        self.plot_confidence_distribution(
            Config.PLOTS_DIR / 'confidence_distribution.png'
        )
        self.plot_red_flags(
            flag_data,
            Config.PLOTS_DIR / 'top_red_flags.png'
        )
        
        print("Generating report...")
        report = self.generate_report(metrics, flag_data, examples)
        
        with open(Config.REPORT_FILE, 'w') as f:
            f.write(report)
        
        print(report)
        print(f"\nAnalysis complete!")
        print(f"Report saved to: {Config.REPORT_FILE}")
        print(f"Plots saved to: {Config.PLOTS_DIR}")


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python analysis.py <results_directory>")
        print("Example: python analysis.py results/")
        sys.exit(1)
    
    results_dir = Path(sys.argv[1])
    
    if not results_dir.exists():
        print(f"Error: Directory not found: {results_dir}")
        sys.exit(1)
    
    print("=" * 70)
    print("LLM-Based Certificate Detection - Results Analysis")
    print("=" * 70)
    print()
    
    try:
        analyzer = ResultsAnalyzer(results_dir)
        analyzer.run_analysis()
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please run main.py first to generate predictions.")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()