# data/validate_dataset.py

import pandas as pd

df = pd.read_csv("data/processed/dataset_clean.csv")

print("=" * 55)
print("WEEK 1 — FINAL DATASET VALIDATION")
print("=" * 55)

print(f"\n Total samples : {len(df)}")
print(f" Columns       : {df.columns.tolist()}")

print(f"\n Label distribution:")
vc = df['label'].value_counts()
print(f"   Safe (0)        : {vc.get(0,0)}  ({vc.get(0,0)/len(df)*100:.1f}%)")
print(f"   Vulnerable (1)  : {vc.get(1,0)}  ({vc.get(1,0)/len(df)*100:.1f}%)")

print(f"\n Language breakdown:")
for lang, count in df['language'].value_counts().items():
    print(f"   {lang:10s}: {count}  ({count/len(df)*100:.1f}%)")

print(f"\n Source breakdown:")
for src, count in df['source'].value_counts().items():
    real_or_synth = "REAL" if "real" in src else "MIXED/SYNTHETIC"
    print(f"   {src:30s}: {count:5d}  [{real_or_synth}]")

print(f"\n Code length stats:")
print(f"   Avg : {df['code'].str.len().mean():.0f} chars")
print(f"   Min : {df['code'].str.len().min()} chars")
print(f"   Max : {df['code'].str.len().max()} chars")

print(f"\n Null check:")
for col, n in df.isnull().sum().items():
    print(f"   {'✓' if n == 0 else '✗'} {col}: {n} nulls")

dupes = df.duplicated(subset=["code"]).sum()
print(f"\n Duplicates : {dupes} {'✓' if dupes == 0 else '⚠ re-run clean_data.py'}")

print(f"\n Top CWE types:")
for cwe, count in df['cwe_id'].value_counts().head(8).items():
    print(f"   {cwe:25s}: {count}")

print("\n" + "=" * 55)
print(" ✓ Week 1 Complete — Dataset pipeline ready")
print("=" * 55)

