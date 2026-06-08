# data/download_datasets.py

import os
import pandas as pd
from datasets import load_dataset

RAW_DIR = "data/raw"
os.makedirs(RAW_DIR, exist_ok=True)

# ─────────────────────────────────────────
# Dataset 1: CVEfixes  ✅ REAL
# Source: GitHub CVE patches from NVD
# ~13k rows — Python, Java, JavaScript + more
# vulnerable_code = buggy code  (label=1)
# fixed_code      = patched code (label=0)
# ─────────────────────────────────────────
print("=" * 55)
print("Downloading Dataset 1: CVEfixes (REAL)")
print("=" * 55)
try:
    cvefixes = load_dataset("hitoshura25/cvefixes")
    split_name = "train" if "train" in cvefixes else list(cvefixes.keys())[0]
    df_cve = cvefixes[split_name].to_pandas()
    df_cve.to_csv(f"{RAW_DIR}/cvefixes_raw.csv", index=False)
    print(f"✓ CVEfixes saved: {len(df_cve)} rows")
    print(f"  Columns  : {df_cve.columns.tolist()}")
    print(f"  Languages: {df_cve['language'].value_counts().head(8).to_dict()}\n")
except Exception as e:
    print(f"✗ CVEfixes failed: {e}\n")


# ─────────────────────────────────────────
# Dataset 2: SecVuln  ⚠️ MIXED
# Source: BigVul (real C/C++) + LLM-generated Python/Java/JS
# ALL 3 splits saved — we merge in clean_data.py
# Splits: train(140k) + validation(17k) + test(17k) = ~175k total
# After filtering Python + Java → expect ~8k-12k rows
# ─────────────────────────────────────────
print("=" * 55)
print("Downloading Dataset 2: SecVuln ALL SPLITS (MIXED)")
print("=" * 55)
try:
    sec_vuln = load_dataset("ayshajavd/code-security-vulnerability-dataset")
    print(f"  Available splits: {list(sec_vuln.keys())}")

    for split in ["train", "validation", "test"]:
        if split in sec_vuln:
            df_split = sec_vuln[split].to_pandas()
            df_split.to_csv(f"{RAW_DIR}/secvuln_{split}_raw.csv", index=False)
            # Show language breakdown per split
            lang_counts = df_split['language'].str.lower().value_counts()
            py  = lang_counts.get('python', 0)
            jav = lang_counts.get('java', 0)
            print(f"  ✓ [{split}] saved: {len(df_split)} rows  |  python={py}  java={jav}")
        else:
            print(f"  ✗ [{split}] not found — skipping")
    print()
except Exception as e:
    print(f"✗ SecVuln failed: {e}\n")


# ─────────────────────────────────────────
# Dataset 3: DetectVul/CVEFixes  ✅ REAL
# Source: CVEFixes base — Python ONLY
# Statement-level labels, variable names anonymized
# ~5.7k rows (train + test combined)
# NOTE: Java not present here — Python only
# ─────────────────────────────────────────
print("=" * 55)
print("Downloading Dataset 3: DetectVul/CVEFixes (REAL, Python only)")
print("=" * 55)
try:
    detectvul = load_dataset("DetectVul/CVEFixes")
    print(f"  Available splits: {list(detectvul.keys())}")

    all_splits = []
    for split in detectvul.keys():
        df_split = detectvul[split].to_pandas()
        df_split["split_origin"] = split
        all_splits.append(df_split)
        print(f"  ✓ [{split}] loaded: {len(df_split)} rows")

    df_dv = pd.concat(all_splits, ignore_index=True)
    df_dv.to_csv(f"{RAW_DIR}/detectvul_raw.csv", index=False)
    print(f"  ✓ DetectVul combined saved: {len(df_dv)} rows")
    print(f"  Columns: {df_dv.columns.tolist()}\n")
except Exception as e:
    print(f"✗ DetectVul failed: {e}\n")


# MickyMike/cvefixes_bigvul was evaluated and removed.
# Its schema uses 'source' col for code and 'target' for diffs —
# designed for patch generation, not binary vulnerability classification.
# Not compatible with our pipeline.


# ─────────────────────────────────────────
# Summary
# ─────────────────────────────────────────
print("=" * 55)
print("All downloads complete. Files in data/raw/:")
for f in sorted(os.listdir(RAW_DIR)):
    if f.endswith(".csv"):
        size_mb = os.path.getsize(f"{RAW_DIR}/{f}") / (1024 * 1024)
        print(f"  {f:50s} {size_mb:.1f} MB")
print("\nNext: python data/clean_data.py")