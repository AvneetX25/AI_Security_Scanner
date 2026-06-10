# Week 3 — Model Evaluation Results

## Dataset
- Total rows: 7,866
- Train: 6,686 | Val: 1,180
- Vulnerable: 2,622 | Safe: 5,244 (1:2 ratio)
- Model: `microsoft/codebert-base`

---

## Before / After Fine-Tuning

| Metric    | Baseline (before) | Fine-tuned (after) | Δ Improvement |
|-----------|-------------------|--------------------|---------------|
| Precision | 0.3314            | 0.8247             | +49.3 pp      |
| Recall    | 1.0000            | 0.8184             | -18.2 pp      |
| F1 Score  | 0.4978            | 0.8216             | +32.4 pp      |
| Loss      | 0.7379            | 0.3136             | -57.5%        |

> Baseline behavior: untrained classifier head flagged everything as vulnerable
> (precision 0.33, recall 1.0) — expected for a randomly initialized head.

---

## Epoch-by-Epoch Progression

| Epoch | Precision | Recall | F1     | Val Loss |
|-------|-----------|--------|--------|----------|
| 1     | 0.7214    | 0.8875 | 0.7959 | 0.3276   |
| 2     | 0.7985    | 0.8210 | 0.8096 | 0.3046   |
| 3     | 0.8247    | 0.8184 | 0.8216 | 0.3136   |

Best checkpoint selected by F1 → Epoch 3.

---

## Final Classification Report (Val set, 1,180 samples)

```
              precision    recall  f1-score   support

    Safe (0)       0.91      0.91      0.91       789
Vuln    (1)       0.82      0.82      0.82       391

    accuracy                           0.88      1180
   macro avg       0.87      0.87      0.87      1180
weighted avg       0.88      0.88      0.88      1180
```

---

## Training Config

| Parameter               | Value                    |
|-------------------------|--------------------------|
| Base model              | microsoft/codebert-base  |
| Epochs                  | 3                        |
| Batch size              | 16                       |
| Max sequence length     | 512                      |
| Eval strategy           | per epoch                |
| Best model metric       | F1                       |
| Mixed precision (fp16)  | Yes                      |

---

## Saved Artifacts

| Artifact                        | Path                          |
|---------------------------------|-------------------------------|
| Fine-tuned model                | `model/checkpoints/final/`    |
| Raw results (JSON)              | `evaluation/results.json`     |
| This report                     | `evaluation/results.md`       |