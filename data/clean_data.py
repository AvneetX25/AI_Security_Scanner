# data/clean_data.py

import pandas as pd
import os
import ast
import re

RAW_DIR = "data/raw"
PROCESSED_DIR = "data/processed"
os.makedirs(PROCESSED_DIR, exist_ok=True)

# ── Only change needed to switch from JS → Java ──
TARGET_LANGUAGES = ["python", "java"]
MIN_LINES = 5
MAX_CHARS  = 4000   # ~512 tokens


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def apply_filters(df, dataset_name):
    before = len(df)
    df = df.dropna(subset=["code", "label", "language"])
    df["language"] = df["language"].str.lower().str.strip()

    # Normalize Java variants
    df["language"] = df["language"].replace({
        "java":       "java",
        "javascript": "javascript",   # will be filtered out
        "python":     "python",
        "python3":    "python",
    })

    df = df[df["language"].isin(TARGET_LANGUAGES)]
    df = df[df["code"].str.strip().str.len() > 0]
    df = df[df["code"].str.count("\n") >= MIN_LINES]
    df = df[df["code"].str.len() <= MAX_CHARS]
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]
    after = len(df)
    print(f"  [{dataset_name}] {before} → {after} rows after filters")
    return df.reset_index(drop=True)


def parse_bool_label(val):
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, str):
        return 1 if val.strip().lower() == "true" else 0
    return int(bool(val))


def parse_list_col(val):
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        val = val.strip()
        try:
            result = ast.literal_eval(val)
            if isinstance(result, list):
                return result
        except Exception:
            pass
        nums = re.findall(r'\d+', val)
        return [int(n) for n in nums]
    return []


# ─────────────────────────────────────────
# DATASET 1: CVEfixes  ✅ REAL
# Python + Java real CVE patches
# ─────────────────────────────────────────
print("\n" + "=" * 55)
print("Processing Dataset 1: CVEfixes (REAL)")
print("=" * 55)

df_cve_raw = pd.read_csv(f"{RAW_DIR}/cvefixes_raw.csv")
print(f"  Raw rows: {len(df_cve_raw)}")
print(f"  All languages: {df_cve_raw['language'].str.lower().value_counts().head(8).to_dict()}")

cve_vulnerable = pd.DataFrame({
    "code":     df_cve_raw["vulnerable_code"],
    "label":    1,
    "language": df_cve_raw["language"],
    "cwe_id":   df_cve_raw["cwe_id"],
    "source":   "cvefixes_real"
})
cve_fixed = pd.DataFrame({
    "code":     df_cve_raw["fixed_code"],
    "label":    0,
    "language": df_cve_raw["language"],
    "cwe_id":   df_cve_raw["cwe_id"],
    "source":   "cvefixes_real"
})

df_cve = pd.concat([cve_vulnerable, cve_fixed], ignore_index=True)
df_cve = apply_filters(df_cve, "CVEfixes")
print(f"  Label split   : {df_cve['label'].value_counts().to_dict()}")
print(f"  Language split: {df_cve['language'].value_counts().to_dict()}")


# ─────────────────────────────────────────
# DATASET 2: SecVuln ALL SPLITS  ⚠️ MIXED
# Python + Java (Java rows were previously discarded)
# ─────────────────────────────────────────
print("\n" + "=" * 55)
print("Processing Dataset 2: SecVuln ALL SPLITS (MIXED)")
print("=" * 55)

sec_frames = []
for split in ["train", "validation", "test"]:
    path = f"{RAW_DIR}/secvuln_{split}_raw.csv"
    if os.path.exists(path):
        df_split = pd.read_csv(path)
        print(f"  Loaded secvuln_{split}: {len(df_split)} rows")
        sec_frames.append(df_split)
    else:
        print(f"  MISSING: {path} — skipping")

df_sec_raw = pd.concat(sec_frames, ignore_index=True)
print(f"  Combined SecVuln total: {len(df_sec_raw)} rows")
print(f"  All languages: {df_sec_raw['language'].str.lower().value_counts().head(8).to_dict()}")

df_sec = pd.DataFrame({
    "code":     df_sec_raw["code"],
    "label":    df_sec_raw["is_vulnerable"].apply(parse_bool_label),
    "language": df_sec_raw["language"],
    "cwe_id":   df_sec_raw["cwe_id"],
    "source":   "secvuln_mixed"
})
df_sec = apply_filters(df_sec, "SecVuln")
print(f"  Label split   : {df_sec['label'].value_counts().to_dict()}")
print(f"  Language split: {df_sec['language'].value_counts().to_dict()}")


# ─────────────────────────────────────────
# DATASET 3: DetectVul  ✅ REAL
# Python only — statement-level, reconstruct to function-level
# ─────────────────────────────────────────
print("\n" + "=" * 55)
print("Processing Dataset 3: DetectVul (REAL, Python only)")
print("=" * 55)

df_dv_raw = pd.read_csv(f"{RAW_DIR}/detectvul_raw.csv")
print(f"  Raw rows: {len(df_dv_raw)}")

def reconstruct_function(lines_val):
    lines = parse_list_col(lines_val)
    return "".join(lines) if lines else ""

def get_function_label(label_val):
    labels = parse_list_col(label_val)
    return 1 if any(l == 1 for l in labels) else 0

dv_records = []
for _, row in df_dv_raw.iterrows():
    dv_records.append({
        "code":     reconstruct_function(row["lines"]),
        "label":    get_function_label(row["label"]),
        "language": "python",
        "cwe_id":   "CVEFixes",
        "source":   "detectvul_real"
    })

df_dv = pd.DataFrame(dv_records)
print(f"  Label dist before filters: {df_dv['label'].value_counts().to_dict()}")
df_dv = apply_filters(df_dv, "DetectVul")
print(f"  Label split: {df_dv['label'].value_counts().to_dict()}")



# ─────────────────────────────────────────
# MERGE ALL
# ─────────────────────────────────────────
print("\n" + "=" * 55)
print("Merging all datasets")
print("=" * 55)

frames_to_merge = [df_cve, df_sec, df_dv]


merged = pd.concat(frames_to_merge, ignore_index=True)
print(f"  Total before dedup : {len(merged)}")

merged = merged.drop_duplicates(subset=["code"])
print(f"  Total after dedup  : {len(merged)}")
print(f"  Source breakdown:\n{merged['source'].value_counts().to_string()}")
print(f"  Language breakdown:\n{merged['language'].value_counts().to_string()}")


# ─────────────────────────────────────────
# BALANCE: 2:1 safe:vulnerable
# ─────────────────────────────────────────
print("\n" + "=" * 55)
print("Balancing dataset (2:1 safe:vulnerable)")
print("=" * 55)

vulnerable    = merged[merged["label"] == 1]
safe          = merged[merged["label"] == 0]
n_vuln        = len(vulnerable)
n_safe_target = min(len(safe), n_vuln * 2)
safe_sampled  = safe.sample(n=n_safe_target, random_state=42)

final = pd.concat([vulnerable, safe_sampled], ignore_index=True)
final = final.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"  Vulnerable  : {n_vuln}")
print(f"  Safe (kept) : {n_safe_target}")
print(f"  Final total : {len(final)}")


# ─────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────
output_path = f"{PROCESSED_DIR}/dataset_clean.csv"
final.to_csv(output_path, index=False)

print("\n" + "=" * 55)
print("FINAL DATASET SUMMARY")
print("=" * 55)
print(f"Total rows    : {len(final)}")
print(f"Columns       : {final.columns.tolist()}")
print(f"\nLabel distribution:\n{final['label'].value_counts().to_string()}")
print(f"\nLanguage breakdown:\n{final['language'].value_counts().to_string()}")
print(f"\nSource breakdown:\n{final['source'].value_counts().to_string()}")
print(f"\nTop CWE types:\n{final['cwe_id'].value_counts().head(10).to_string()}")
print(f"\nAvg code length : {final['code'].str.len().mean():.0f} chars")
print(f"Min code length : {final['code'].str.len().min()} chars")
print(f"Max code length : {final['code'].str.len().max()} chars")
print(f"\n✓ Saved to {output_path}")