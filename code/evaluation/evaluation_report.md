# Evaluation report

## Full-dataset output validation

The final deterministic run processed all 518 requests and wrote a root-level
`output.csv`. The output validator confirmed the required header, exact case
coverage, sorted rows, valid JSON arrays, step numbering, allowed operation/state
pairs, phase order, evidence IDs, evidence capture cutoffs, and required evidence
handling for complete and not-applicable cases.

| Result | Count |
| --- | ---: |
| `COMPLETE` | 47 |
| `INCOMPLETE` | 450 |
| `NOT_APPLICABLE` | 21 |
| Total rows | 518 |

The dataset does not provide canonical labels for all 518 evaluation requests.
Accordingly, accuracy below is measured only against the 32 public sample
answers; full-run structural validation is not represented as semantic accuracy.

## Public sample metrics

The generated output for `sample_deletion_requests.csv` was compared with
`sample_output.csv`.

| Metric | Result | Definition |
| --- | ---: | --- |
| Case-level deletion-status accuracy | 24/32 (75.00%) | Exact status matches |
| Position-aligned step accuracy | 107/194 (55.15%) | Exact step objects at the same index, with missing step positions counted incorrect |
| Position-aligned field accuracy | 873/1,358 (64.29%) | Exact field matches at the same step index; missing step positions count as incorrect |
| Exact sequence accuracy | 7/32 (21.88%) | Entire ordered step arrays match exactly |

These figures reflect the final sample run. Step and field metrics are
position-aligned rather than edit-distance-aligned.

## Additional participant-created evaluation cases

The evaluation runner includes four deletion-intent cases independent of the
public sample and checks them against `is_deletion_request`:

| Case | Expected | Actual | Result |
| --- | --- | --- | --- |
| Explicit English account and personal-data deletion | Authorizes deletion | Authorizes deletion | PASS |
| Spanish request to delete an account and personal data | Authorizes deletion | Authorizes deletion | PASS |
| Data-export request explicitly not requesting deletion | Not applicable | Not applicable | PASS |
| Marketing-email unsubscribe while keeping the account active | Not applicable | Not applicable | PASS |

Run the custom cases along with output validation using
`python code/evaluation/main.py`.

## Failures found and improvements made

- Added trace correlation so a completed lookup inherits its subject lookup key
  from the matching started event, including start events without a resource ID.
- Added parsing for timestamp-prefixed JSON log entries and separated evidence
  availability time from the event time used to select the latest state.
- Added generic classification for contact-index lookup results and interpreted
  eligible, unblocked backup candidates as restore risks.
- Added local Tesseract discovery for PNG evidence while keeping OCR optional.
- Added explicit negative-intent handling for requests that say they are not
  asking for deletion.
- Removed a fabricated account-absence fallback that inferred resource IDs from
  user-number patterns rather than participant-facing evidence.

Remaining limitations are material: eight public sample statuses differ from the
reference, exact step-sequence accuracy is 7/32, and some records in evidence
exports are not directly attributable to a subject through the participant-facing
identifiers available to this engine. In the full run, 124 `INCOMPLETE` rows
have no evidence-backed finding because the linked evidence does not establish a
policy violation; the output avoids inventing a resource or citing unrelated
evidence. These rows need additional evidence linkage or more complete evidence
interpretation before this implementation can be considered a high-accuracy
submission.
