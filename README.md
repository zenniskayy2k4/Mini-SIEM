# xAI Malware Hunter

![xAI Malware Hunter Logo](./assets/logo.png)

A professional, explainable AI (xAI) tool for malware detection on **Windows PE** and **Android APK** files. 

This project leverages **LightGBM** trained on the massive **EMBER 2018 dataset**, combined with **SHAP (SHapley Additive exPlanations)** to provide transparent, human-readable reasons for every detection verdict. It features a custom pure-Python feature extractor, eliminating the need for complex C++ dependencies.

## 🚀 Key Features

*   **High Accuracy Detection:** Powered by a LightGBM model trained on ~600k-800k samples (EMBER Dataset), achieving **F1-Score > 90%**.
*   **Explainable AI (xAI):** Doesn't just say "Malware" or "Benign". It explains *why* using SHAP values (e.g., "High Entropy", "Anomalous Byte Histogram").
*   **Human-Readable Reports:** Translates technical feature names (e.g., `ByteHist_106`) into understandable insights (e.g., "Suspicious byte frequency typical of packed code").
*   **Multi-Platform Architecture:**
    *   **Windows PE:** Native support using a custom, pure-Python implementation of the EMBER feature extractor.
    *   **Android APK:** Experimental support using `androguard` with feature alignment techniques.
*   **Lightweight & Fast:** Optimized `numpy` vectorization for feature extraction. No heavy LLMs or C++ compilers required.
*   **Production-Ready Structure:** Clean MVC-like architecture (Extractor -> Engine -> View).

## 📂 Project Structure

```text
xai-malware-hunter/
│
├── config/
│   └── .env                # API Keys (VirusTotal - Optional)
│
├── data/
│   └── cache_huggingface/  # Local cache for training data
│
├── models/
│   ├── lgbm_pe_model.pkl      # Trained Windows Model Bundle (Model + Feature Names)
│   └── lgbm_apk_model.pkl     # Trained APK Model Bundle
│
├── src/
│   ├── advanced_extractor.py # Factory for PE/APK extraction
│   ├── ember.py              # Custom Pure-Python EMBER implementation
│   ├── ml_engine.py          # Core Logic (Load Model, Predict, SHAP)
│   └── config_loader.py      # Config management
│
├── train_model.py          # Training script (supports HuggingFace Streaming)
├── main.py                 # Main CLI application
└── requirements.txt        # Python dependencies
```

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/zenniskayy2k4/xAI-Malware-Hunter.git
    cd xai-malware-hunter
    ```

2.  **Install dependencies (Python 3.10+):**
    ```bash
    pip install -r requirements.txt
    ```

3.  **(Optional) Configuration:**
    Create a `.env` file in `config/` if you plan to extend with VirusTotal integration.

## ⚡ Usage

### 1. Analysis (Scan a File)
To scan a file and generate an xAI report:

```bash
python main.py "path/to/suspect_file.exe"
```

**Output Example:**
```text
========== xAI MALWARE HUNTER - ANALYSIS REPORT ==========
Target File: calc.exe

[1] Extracting Features...
----------------------------------------
VERDICT:  BENIGN (SAFE) 
Confidence Score: 99.85%
----------------------------------------

[4] xAI Explanation (Why?)
Feature Name              | Impact     | Reasoning
-------------------------------------------------------------------------------------
ByteHist_255              | Safe/Benign | Standard structure found in legitimate software.
MinEntropy                | Safe/Benign | Normal code density.
...

[5] Generating Report Image...
Saved visual report to 'scan_report.png'
```

### 2. Training the Model (Optional)
If you want to retrain the model from scratch using the EMBER dataset from Hugging Face:

```bash
python train_model.py
```
*Note: This script uses dataset streaming to handle large data (GBs) efficiently without overloading RAM.*

## 🧠 Technical Details

*   **Model:** LightGBM Classifier (Gradient Boosting Decision Tree).
*   **Dataset:** [EMBER 2018 (Malware/Benign)](https://huggingface.co/datasets/cw1521/ember2018-malware-v2).
*   **Input Vector:** 272 Dimensions (256 Byte Histogram + 16 Metadata/Entropy stats).
*   **Explainability:** SHAP TreeExplainer for global and local feature importance.

## 🤝 Contributing
Contributions are welcome! Please fork the repository and submit a Pull Request.

## 📜 License
MIT License.