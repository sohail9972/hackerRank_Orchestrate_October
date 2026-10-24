"""Validate deletion-audit output and compare it with the public sample."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = ROOT / "code"
sys.path.insert(0, str(CODE_DIR))
import main as audit_engine

EXPECTED_COLUMNS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}
OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return reader.fieldnames or [], list(reader)


def validate_output(
    output_path: Path,
    input_path: Path,
    manifest_path: Path,
) -> list[str]:
    errors: list[str] = []
    columns, output_rows = read_csv(output_path)
    _, input_rows = read_csv(input_path)
    _, manifest_rows = read_csv(manifest_path)
    requests_by_id = {row["case_id"]: row for row in input_rows}
    if columns != EXPECTED_COLUMNS:
        errors.append(f"Output columns must be {EXPECTED_COLUMNS}, got {columns}.")

    input_ids = [row["case_id"] for row in input_rows]
    output_ids = [row.get("case_id", "") for row in output_rows]
    if len(output_rows) != len(input_rows):
        errors.append(f"Expected {len(input_rows)} rows, got {len(output_rows)}.")
    if output_ids != sorted(output_ids):
        errors.append("Output rows are not sorted by case_id.")
    if len(set(output_ids)) != len(output_ids):
        errors.append("Output contains duplicate case_id values.")
    if set(output_ids) != set(input_ids):
        errors.append("Output case_id values do not exactly match the input.")

    known_evidence = {row["file_id"] for row in manifest_rows}
    evidence_capture = {
        row["file_id"]: row.get("captured_at", "") for row in manifest_rows
    }
    for row in output_rows:
        case_id = row.get("case_id", "<missing>")
        status = row.get("deletion_status", "")
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{case_id}: invalid deletion_status {status!r}.")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except json.JSONDecodeError as exc:
            errors.append(f"{case_id}: invalid steps_json ({exc}).")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json must be a JSON array.")
            continue
        if status == "NOT_APPLICABLE":
            if steps:
                errors.append(f"{case_id}: NOT_APPLICABLE must have no steps.")
            continue

        phase_order = [PHASE_ORDER.get(step.get("phase"), -1) for step in steps if isinstance(step, dict)]
        if phase_order != sorted(phase_order):
            errors.append(f"{case_id}: phases are not ordered FINDING/REMEDIATION/VERIFICATION.")
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                errors.append(f"{case_id}: step {index} is not an object.")
                continue
            if set(step) != STEP_FIELDS:
                errors.append(f"{case_id}: step {index} fields do not match the required schema.")
                continue
            if step["step_no"] != index:
                errors.append(f"{case_id}: step numbers are not consecutive at {index}.")
            phase, operation = step["phase"], step["operation"]
            expected_state = OPERATIONS.get(phase, {}).get(operation)
            if expected_state is None:
                errors.append(f"{case_id}: unsupported operation {phase}/{operation}.")
            elif step["state"] != expected_state:
                errors.append(
                    f"{case_id}: invalid state {step['state']!r} for {operation}."
                )
            evidence_id = step["evidence_id"]
            if evidence_id and evidence_id not in known_evidence:
                errors.append(f"{case_id}: unknown evidence_id {evidence_id!r}.")
            if evidence_id and evidence_id in evidence_capture:
                audit_at = requests_by_id.get(case_id, {}).get("audit_at", "")
                try:
                    capture_time = dt.datetime.fromisoformat(
                        evidence_capture[evidence_id].replace("Z", "+00:00")
                    )
                    audit_time = dt.datetime.fromisoformat(
                        audit_at.replace("Z", "+00:00")
                    )
                except ValueError:
                    capture_time = audit_time = None
                if capture_time and audit_time and capture_time > audit_time:
                    errors.append(
                        f"{case_id}: cited evidence {evidence_id} was captured after audit_at."
                    )
            if status == "COMPLETE":
                if phase != "VERIFICATION" or not evidence_id:
                    errors.append(
                        f"{case_id}: COMPLETE steps must be evidence-backed verifications."
                    )
            elif phase == "FINDING" and not evidence_id:
                errors.append(f"{case_id}: finding step {index} has no evidence_id.")
            elif phase in {"REMEDIATION", "VERIFICATION"} and evidence_id:
                errors.append(
                    f"{case_id}: future {phase.lower()} step {index} must have empty evidence_id."
                )
    return errors


def compare_sample(actual_path: Path, reference_path: Path) -> dict[str, Any]:
    _, actual_rows = read_csv(actual_path)
    _, reference_rows = read_csv(reference_path)
    actual = {row["case_id"]: row for row in actual_rows}
    reference = {row["case_id"]: row for row in reference_rows}
    common = sorted(actual.keys() & reference.keys())
    status_correct = sum(
        actual[key]["deletion_status"] == reference[key]["deletion_status"]
        for key in common
    )
    sequence_correct = 0
    step_slots_correct = 0
    step_slots_total = 0
    field_correct = 0
    field_total = 0
    for key in common:
        actual_steps = json.loads(actual[key]["steps_json"])
        expected_steps = json.loads(reference[key]["steps_json"])
        sequence_correct += actual_steps == expected_steps
        slot_count = max(len(actual_steps), len(expected_steps))
        step_slots_total += slot_count
        field_total += slot_count * len(STEP_FIELDS)
        for index in range(slot_count):
            if index >= len(actual_steps) or index >= len(expected_steps):
                continue
            left, right = actual_steps[index], expected_steps[index]
            step_slots_correct += left == right
            field_correct += sum(left.get(field) == right.get(field) for field in STEP_FIELDS)
    return {
        "cases": len(common),
        "status_correct": status_correct,
        "sequence_correct": sequence_correct,
        "step_slots_correct": step_slots_correct,
        "step_slots_total": step_slots_total,
        "field_correct": field_correct,
        "field_total": field_total,
    }


def print_metrics(metrics: dict[str, Any]) -> None:
    cases = metrics["cases"]
    print(f"Case-level status accuracy: {metrics['status_correct']}/{cases}")
    print(f"Exact sequence accuracy: {metrics['sequence_correct']}/{cases}")
    print(
        "Position-aligned step accuracy: "
        f"{metrics['step_slots_correct']}/{metrics['step_slots_total']}"
    )
    print(
        "Position-aligned field accuracy: "
        f"{metrics['field_correct']}/{metrics['field_total']}"
    )


def run_custom_cases() -> list[tuple[str, bool, bool]]:
    cases = (
        (
            "explicit deletion request",
            "Please erase my account and delete the personal data linked to it.",
            True,
        ),
        (
            "Spanish deletion request",
            "Solicito la eliminación de mi cuenta y de mis datos personales.",
            True,
        ),
        (
            "data access request",
            "Please export a copy of my personal data; I am not requesting deletion.",
            False,
        ),
        (
            "marketing opt-out",
            "Unsubscribe me from marketing emails and keep my account active.",
            False,
        ),
    )
    return [
        (name, expected, audit_engine.is_deletion_request(text))
        for name, text, expected in cases
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    parser.add_argument(
        "--input", type=Path, default=ROOT / "dataset" / "deletion_requests.csv"
    )
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "dataset" / "evidence_files.csv"
    )
    parser.add_argument(
        "--sample-reference",
        type=Path,
        default=ROOT / "dataset" / "sample_output.csv",
    )
    parser.add_argument("--skip-sample-comparison", action="store_true")
    args = parser.parse_args()
    errors = validate_output(args.output, args.input, args.manifest)
    if errors:
        print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
        return 1
    print(f"Valid output: {args.output}")
    custom_cases = run_custom_cases()
    for name, expected, actual in custom_cases:
        print(
            f"Custom case {name}: {'PASS' if expected == actual else 'FAIL'} "
            f"(expected={expected}, actual={actual})"
        )
    if any(expected != actual for _, expected, actual in custom_cases):
        return 1
    if not args.skip_sample_comparison and args.input.name == "sample_deletion_requests.csv":
        print_metrics(compare_sample(args.output, args.sample_reference))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())