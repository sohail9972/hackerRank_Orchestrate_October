# Usage report

## Final full-dataset run

| Item | Usage |
| --- | ---: |
| Requests processed | 518 |
| Evidence manifest entries available | 94 |
| Model provider | None; local deterministic Python implementation |
| Model name | None |
| Model/API calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total model cost | $0.00 |
| Estimated model cost per request | $0.00 |

No external language model or hosted API was used, so there are no per-model
totals to report. The solution ran locally with Python 3.13 and `pypdf` for PDF
text extraction. Tesseract OCR is optional and is used only when a local
executable is available.

The full run generated the root `output.csv`; the evaluation runner then
validated the 518-row output contract. Token and cost totals above refer only to
model usage, not local CPU time or software installation.
