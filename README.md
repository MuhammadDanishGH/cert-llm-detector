# LLM-Based TLS Certificate Phishing Detection

A novel approach to detecting phishing TLS certificates using **pure semantic analysis** powered by Google's Gemini LLM. Unlike traditional rule-based or statistical methods, this system identifies suspicious certificates through linguistic and contextual anomaly detection.

## 🎯 Key Features

- **Pure LLM-Based Detection**: No rules, no regex, no statistical thresholds
- **Semantic Anomaly Detection**: Identifies unnatural domain patterns, organizational mismatches, and linguistic inconsistencies
- **Comprehensive Analysis**: Detailed metrics, visualizations, and misclassification reports
- **Free Tier Compatible**: Designed to work with Gemini's free API tier
- **Production Ready**: Batch processing, error handling, rate limiting, and progress tracking

## 🏗️ Architecture
```
┌─────────────────┐
│  Certificate    │
│  Files (ASCII)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Certificate    │
│  Loader         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Gemini API     │
│  (Semantic      │
│   Analysis)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Structured     │
│  Predictions    │
│  (JSON→CSV)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Performance    │
│  Analysis &     │
│  Visualization  │
└─────────────────┘
```

## 📋 Prerequisites

- Python 3.8 or higher
- Gemini API key ([Get one free](https://ai.google.dev/))
- ~266K TLS certificate files (not included)

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/llm-cert-phishing-detection.git
cd llm-cert-phishing-detection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up your Gemini API key

**Option A: Environment variable**
```bash
export GEMINI_API_KEY='your-api-key-here'
```

**Option B: .env file**
```bash
echo "GEMINI_API_KEY=your-api-key-here" > .env
```

### 4. Prepare your dataset

Organize your certificates in the following structure:
```
certificates/
├── phishing-certificates/
│   ├── cert_file_1
│   ├── cert_file_2
│   └── ...
└── benign-certificates/
    ├── cert_file_1
    ├── cert_file_2
    └── ...
```

**Note**: Certificate files should be raw ASCII text without extensions.

## 📊 Usage

### Step 1: Run Detection

Analyze all certificates and generate predictions:
```bash
python main.py certificates/
```

**What happens:**
- Loads certificates from both directories
- Sends each to Gemini API for semantic analysis
- Saves predictions to `results/predictions.csv`
- Creates detailed logs in `results/logs/`

**Output:**
```
results/
├── predictions.csv          # Main results file
├── predictions_temp.csv     # Intermediate saves (auto-backup)
└── logs/
    └── detection_YYYYMMDD_HHMMSS.log
```

### Step 2: Analyze Results

Generate comprehensive performance metrics and visualizations:
```bash
python analysis.py results/
```

**What happens:**
- Computes accuracy, precision, recall, F1
- Generates confusion matrix
- Analyzes confidence distributions
- Identifies common red flags
- Finds misclassification examples

**Output:**
```
results/
└── analysis/
    ├── report.txt                      # Comprehensive text report
    └── plots/
        ├── confusion_matrix.png        # Classification performance
        ├── confidence_distribution.png # Confidence score analysis
        └── top_red_flags.png          # Most common phishing indicators
```

## 📈 Interpreting Results

### Predictions CSV

Each row contains:
- `filename`: Certificate filename
- `true_label`: Ground truth (phishing/benign)
- `predicted_label`: LLM prediction
- `confidence`: Confidence score (0.0-1.0)
- `reasoning`: LLM's explanation
- `red_flags`: JSON array of identified concerns
- `domain_analysis`: Domain-specific evaluation
- `organization_analysis`: Organizational field evaluation

### Performance Metrics

**Accuracy**: Overall correctness  
**Precision**: Of predicted phishing, how many were actually phishing?  
**Recall**: Of actual phishing, how many did we detect?  
**F1-Score**: Harmonic mean of precision and recall

### Visualizations

1. **Confusion Matrix**: Shows TP, TN, FP, FN breakdown
2. **Confidence Distribution**: Analyzes prediction certainty
3. **Red Flags**: Most common phishing indicators found

## 🔧 Configuration

Edit `config.py` to customize:
```python
# API Settings
GEMINI_MODEL = "gemini-1.5-flash"  # or "gemini-1.5-pro"
MAX_REQUESTS_PER_MINUTE = 15
REQUEST_DELAY_SECONDS = 4

# Processing
BATCH_SIZE = 100
MAX_RETRIES = 3
MAX_CERT_SIZE = 10000  # bytes
```

## 🧠 How It Works

### Semantic Detection Strategy

The LLM analyzes certificates for:

1. **Domain Anomalies**
   - Homograph attacks (paypa1.com)
   - Typosquatting (gooogle.com)
   - Suspicious TLDs or subdomain chains

2. **Organizational Inconsistencies**
   - Org name doesn't match domain
   - Generic/fake organization names
   - Mismatched geographic info

3. **Linguistic Red Flags**
   - Grammatical errors
   - Machine-generated patterns
   - Character encoding issues

4. **Certificate Metadata**
   - Unusual validity periods
   - Free CA for enterprise brands
   - Multiple unrelated SANs

5. **Contextual Analysis**
   - Brand impersonation patterns
   - Certificate type mismatches

### Example LLM Response
```json
{
  "label": "phishing",
  "confidence": 0.92,
  "reasoning": "Domain 'paypa1-secure-login.com' uses number substitution (1 for l) to impersonate PayPal. Organization field claims 'PayPal Inc' but certificate is issued by a free DV CA, inconsistent with a major enterprise.",
  "red_flags": [
    "Homograph attack detected",
    "Organization-domain mismatch",
    "Free CA for claimed enterprise"
  ],
  "domain_analysis": "Suspicious typosquatting pattern targeting PayPal",
  "organization_analysis": "Fake organizational claim"
}
```

## ⚡ Performance Tips

### For Large Datasets

1. **Process in batches**: The system auto-saves every 100 certificates
2. **Monitor progress**: Use `tail -f results/logs/*.log`
3. **Resume after interruption**: Remove processed files from temp CSV

### Rate Limiting

Gemini free tier limits:
- 15 requests per minute
- 1,500 requests per day

Adjust `REQUEST_DELAY_SECONDS` in config.py if you hit limits.

### Cost Optimization

- Use `gemini-1.5-flash` (faster, cheaper)
- Reduce `MAX_CERT_SIZE` to skip large certs
- Sample dataset for initial testing

## 🐛 Troubleshooting

### "GEMINI_API_KEY not found"
```bash
export GEMINI_API_KEY='your-key'
# or create .env file
```

### "Rate limit exceeded"
Increase `REQUEST_DELAY_SECONDS` in config.py

### "JSON parse error"
LLM occasionally returns malformed JSON. The system retries with fallback prompts.

### Low accuracy?
- Check prompt templates in `prompt_templates.py`
- Verify certificate format (should be ASCII)
- Ensure ground truth labels are correct

## 🔬 Research Applications

This system demonstrates:
- LLM-based security analysis
- Semantic anomaly detection
- Zero-shot classification
- Contextual threat assessment

Ideal for:
- Academic research on LLM security applications
- Benchmark comparisons vs. rule-based systems
- Explainable AI in cybersecurity
- Prompt engineering case studies

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Enhanced prompt engineering
- Multi-model ensemble approaches
- Active learning workflows
- Real-time detection integration

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This is a research tool. For production security systems:
- Combine with cryptographic validation
- Use multiple detection layers
- Implement human review for high-stakes decisions
- Follow security best practices

## 🆘 Support

- **Email**: danish.ejaz99@gmail.com

---
