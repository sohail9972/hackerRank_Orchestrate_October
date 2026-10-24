"""Deterministic deletion audit for the Ghost Data Still Exists challenge."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE = DATASET / "evidence"
OUTPUT = ROOT / "output.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

IDENTIFIER_KEYS = {
    "email",
    "email_hash",
    "phone",
    "name",
    "full_name",
    "display_name",
    "requester_email",
    "requester_phone",
    "requester_name",
    "owner_email",
    "owner_phone",
    "customer_email",
    "customer_reference",
    "subject_reference",
    "subject_ref",
    "user_id",
    "user_reference",
    "lookup_key",
    "lookup_value",
    "correlation_key",
    "owner_reference",
    "customer_id",
}
REFERENCE_KEYS = {
    "customer_reference",
    "subject_reference",
    "subject_ref",
    "user_id",
    "user_reference",
    "owner_reference",
    "customer_id",
}
PII_KEYS = {
    "email",
    "email_hash",
    "phone",
    "name",
    "full_name",
    "display_name",
    "requester_email",
    "requester_phone",
    "requester_name",
    "owner_email",
    "owner_phone",
    "customer_email",
}
KNOWN_SYSTEMS = {
    "account_service",
    "identity_service",
    "search_service",
    "analytics_platform",
    "support_platform",
    "export_service",
    "integration_service",
    "backup_service",
    "security_service",
    "marketing_service",
    "email_delivery_service",
    "cache_service",
}


@dataclass(frozen=True)
class Observation:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    captured_at: str
    source_family: str
    fields: dict[str, Any]
    has_pii: bool = False
    linked_by_reference: bool = False
    available_at: str = ""


@lru_cache(maxsize=None)
def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalized(value: Any) -> str:
    return str(value).strip().casefold() if value is not None else ""


def value_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for child in value.values():
            yield from value_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from value_strings(child)
    elif value is not None:
        yield str(value)


def flatten_fields(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(child, (str, int, float, bool)) or child is None:
                    result.setdefault(str(key).casefold(), child)
                else:
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return result


def _key_value_pairs(line: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    pattern = re.compile(r'([A-Za-z_][\w.-]*)=(?:"([^"]*)"|\'([^\']*)\'|([^\s|]+))')
    for match in pattern.finditer(line):
        pairs[match.group(1).casefold()] = next(
            item for item in match.groups()[1:] if item is not None
        )
    return pairs


def _system_from_text(value: str) -> str:
    text = value.casefold()
    aliases = (
        ("account", "account_service"),
        ("identity", "identity_service"),
        ("search", "search_service"),
        ("analytics", "analytics_platform"),
        ("support", "support_platform"),
        ("export", "export_service"),
        ("connector", "integration_service"),
        ("integration", "integration_service"),
        ("backup", "backup_service"),
        ("security", "security_service"),
        ("marketing", "marketing_service"),
        ("email_delivery", "email_delivery_service"),
        ("cache", "cache_service"),
    )
    for marker, system in aliases:
        if marker in text:
            return system
    return ""


def _category(system: str, collection: str, fields: dict[str, Any]) -> str:
    event = normalized(
        fields.get("_trace_start_event") or fields.get("event")
    )
    if "contact_query" in event or "contact_lookup" in event:
        return "SECONDARY_IDENTIFIER"
    text = " ".join(
        str(value)
        for value in (
            system,
            collection,
            fields.get("record_type", ""),
            fields.get("event", ""),
            fields.get("resource_id", ""),
        )
    ).casefold()
    explicit = normalized(fields.get("record_type"))
    if explicit:
        category_map = {
            "user_profile": "USER_PROFILE",
            "search_index_entry": "SEARCH_INDEX_ENTRY",
            "support_message": "SUPPORT_MESSAGE",
            "support_attachment": "SUPPORT_ATTACHMENT",
            "user_export": "USER_EXPORT",
            "analytics_profile": "ANALYTICS_PROFILE",
            "product_telemetry": "PRODUCT_TELEMETRY",
            "security_audit_log": "SECURITY_AUDIT_LOG",
            "backup_archive": "BACKUP_ARCHIVE",
            "data_flow": "DATA_FLOW",
            "account_tombstone": "ACCOUNT_TOMBSTONE",
            "email_delivery_log": "EMAIL_DELIVERY_LOG",
            "marketing_profile": "MARKETING_PROFILE",
            "cache_entry": "CACHE_ENTRY",
        }
        if explicit in category_map:
            return category_map[explicit]
    for marker, category in (
        ("tombstone", "ACCOUNT_TOMBSTONE"),
        ("backup", "BACKUP_ARCHIVE"),
        ("connector", "DATA_FLOW"),
        ("data_flow", "DATA_FLOW"),
        ("security_audit", "SECURITY_AUDIT_LOG"),
        ("audit_record", "SECURITY_AUDIT_LOG"),
        ("support_attachment", "SUPPORT_ATTACHMENT"),
        ("attachment", "SUPPORT_ATTACHMENT"),
        ("support", "SUPPORT_MESSAGE"),
        ("search", "SEARCH_INDEX_ENTRY"),
        ("analytics", "ANALYTICS_PROFILE"),
        ("telemetry", "PRODUCT_TELEMETRY"),
        ("export", "USER_EXPORT"),
        ("marketing", "MARKETING_PROFILE"),
        ("email_delivery", "EMAIL_DELIVERY_LOG"),
        ("cache", "CACHE_ENTRY"),
        ("profile", "USER_PROFILE"),
        ("account", "USER_PROFILE"),
    ):
        if marker in text:
            return category
    return ""


def _state(fields: dict[str, Any], category: str, line: str = "") -> str:
    values = {key: normalized(value) for key, value in fields.items()}
    combined = " ".join(values.values()) + " " + line.casefold()
    status_code = values.get("status_code", values.get("http_status", ""))
    if status_code == "404" or any(
        marker in combined
        for marker in ("not_found", "not found", "result=miss", "rows=0")
    ):
        return "ABSENT"
    if status_code == "200":
        if category == "USER_PROFILE":
            return "PRESENT"
    if category == "DATA_FLOW":
        enabled = values.get("enabled")
        if enabled in {"1", "true", "yes", "active"} or values.get("result") == "active" or "state=active" in combined:
            return "ACTIVE"
        if enabled in {"0", "false", "no", "disabled"} or values.get("result") == "disabled" or "state=disabled" in combined:
            return "DISABLED"
    if category == "BACKUP_ARCHIVE":
        allowed = values.get("restore_allowed")
        eligible = values.get("eligible")
        deletion_block = values.get("deletion_block")
        if eligible in {"1", "true", "yes"} and deletion_block in {
            "0",
            "false",
            "no",
        }:
            return "ACTIVE"
        if deletion_block in {"1", "true", "yes", "blocked"}:
            return "BLOCKED"
        if allowed in {"1", "true", "yes", "allowed"} or values.get("result") == "active" or "state=active" in combined:
            return "ACTIVE"
        if allowed in {"0", "false", "no", "blocked"} or values.get("result") == "blocked" or "state=blocked" in combined:
            return "BLOCKED"
    if values.get("result") in {"identifiable", "found"} and category not in {
        "SECURITY_AUDIT_LOG",
        "DATA_FLOW",
        "BACKUP_ARCHIVE",
    }:
        return "PRESENT"
    if any(marker in combined for marker in ("redacted", "redacted=true", "pii_status=redacted")):
        return "REDACTED"
    if any(marker in combined for marker in ("anonymized", "anonymised")):
        return "ANONYMIZED"
    if any(marker in combined for marker in ("not_found", "not found", "status_code=404")):
        return "ABSENT"
    if category == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    if category:
        return "PRESENT"
    return ""


def _record_observation(
    raw: Any,
    system: str,
    collection: str,
    evidence_id: str,
    captured_at: str,
    source_family: str,
    line: str = "",
    available_at: str = "",
) -> Observation | None:
    fields = flatten_fields(raw)
    resource_id = str(fields.get("resource_id") or "").strip()
    if not resource_id:
        return None
    system = system or _system_from_text(" ".join(str(x) for x in fields.values()))
    category = _category(system, collection, fields)
    if not system or not category:
        return None
    has_pii = any(
        normalized(fields.get(key))
        and normalized(fields.get(key)) not in {"null", "none", "redacted"}
        for key in PII_KEYS
    )
    state = _state(fields, category, line)
    if not state:
        return None
    linked = any(
        normalized(fields.get(key)).startswith("user_")
        for key in REFERENCE_KEYS
    )
    return Observation(
        system,
        resource_id,
        category,
        state,
        evidence_id,
        captured_at,
        source_family,
        fields,
        has_pii,
        linked,
        available_at or captured_at,
    )


def _json_observations(
    obj: Any, evidence_id: str, captured_at: str, path_name: str
) -> list[Observation]:
    observations: list[Observation] = []

    def visit(
        node: Any,
        system: str = "",
        collection: str = "",
        family: str = "",
    ) -> None:
        if isinstance(node, dict):
            node_system = str(node.get("data_store") or node.get("system") or system)
            node_system = node_system if node_system in KNOWN_SYSTEMS else system
            node_collection = str(node.get("collection") or collection)
            next_family = family or f"{node_system}:{node_collection or path_name}"
            if "resource_id" in node:
                fields = flatten_fields(node)
                observation = _record_observation(
                    node,
                    node_system,
                    node_collection,
                    evidence_id,
                    str(fields.get("observed_at") or captured_at),
                    next_family,
                    available_at=captured_at,
                )
                if observation:
                    observations.append(observation)
            for key, child in node.items():
                child_system = key if key in KNOWN_SYSTEMS else node_system
                child_collection = key if key not in KNOWN_SYSTEMS else node_collection
                child_family = (
                    f"{child_system}:{key}"
                    if key in KNOWN_SYSTEMS
                    else next_family
                )
                visit(child, child_system, child_collection, child_family)
        elif isinstance(node, list):
            for child in node:
                visit(child, system, collection, family)

    visit(obj)
    return observations


def _sql_observations(
    path: Path, evidence_id: str, captured_at: str
) -> list[Observation]:
    connection = sqlite3.connect(":memory:")
    observations: list[Observation] = []
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for (table,) in tables:
            if table == "snapshot_scope":
                continue
            columns = [
                row[1]
                for row in connection.execute(f'PRAGMA table_info("{table}")')
            ]
            for row in connection.execute(f'SELECT * FROM "{table}"'):
                fields = dict(zip(columns, row))
                record_json = fields.get("record_json")
                if record_json:
                    try:
                        fields.update(json.loads(record_json))
                    except json.JSONDecodeError:
                        continue
                system = str(fields.get("origin_system") or "")
                if system not in KNOWN_SYSTEMS:
                    system = _system_from_text(table)
                collection = str(fields.get("collection_name") or table)
                family = f"{system}:{table}"
                observation = _record_observation(
                    fields,
                    system,
                    collection,
                    evidence_id,
                    captured_at,
                    family,
                )
                if observation:
                    observations.append(observation)
    finally:
        connection.close()
    return observations


def _text_observations(
    text: str, evidence_id: str, captured_at: str, path_name: str
) -> list[Observation]:
    observations: list[Observation] = []
    trace_context: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(\{.*\})$",
            line.strip(),
        )
        fields: dict[str, Any]
        if timestamp_match:
            try:
                payload = json.loads(timestamp_match.group(2))
            except json.JSONDecodeError:
                fields = _key_value_pairs(line)
            else:
                fields = flatten_fields(payload)
                fields["event_time"] = timestamp_match.group(1)
        else:
            fields = _key_value_pairs(line)
        if "|" in line and not fields:
            parts = [part.strip() for part in line.split("|")]
            timestamp = parts[0].lstrip("- ")
            if len(parts) >= 6 and timestamp.startswith("20"):
                fields.update(
                    {
                        "event_time": timestamp,
                        "system": parts[1],
                        "resource_id": parts[2],
                        "record_type": parts[3],
                        "result": parts[4],
                        "lookup_value": parts[5],
                    }
                )
        event = str(fields.get("event", "")).casefold()
        trace_id = fields.get("trace_id", "")
        if event.endswith("_started") or event.endswith("_query_started"):
            if trace_id:
                trace_context[trace_id] = fields
            continue
        if trace_id in trace_context:
            start_fields = trace_context[trace_id]
            fields = {**start_fields, **fields}
            fields["_trace_start_event"] = start_fields.get("event", "")
        if not fields.get("resource_id"):
            continue
        system = str(fields.get("service") or fields.get("system") or "")
        if system not in KNOWN_SYSTEMS:
            system = _system_from_text(f"{system} {line}")
        category = _category(system, path_name, fields)
        if not category:
            continue
        if str(fields.get("event", "")).casefold().endswith("_started"):
            continue
        observed_at = fields.get("event_time") or fields.get("timestamp") or captured_at
        observation = _record_observation(
            fields,
            system,
            path_name,
            evidence_id,
            observed_at,
            f"{system}:trace",
            line,
            captured_at,
        )
        if observation:
            observations.append(observation)
    return observations


def _document_observations(
    text: str, evidence_id: str, captured_at: str, path_name: str
) -> list[Observation]:
    observations: list[Observation] = []
    for match in re.finditer(
        r"\b(account|search|analytics|support|export|data_flow|backup|"
        r"audit_record|tombstone|marketing|cache|email_delivery)_\d+\b",
        text,
        re.IGNORECASE,
    ):
        resource_id = match.group(0)
        prefix = next(
            key
            for key in (
                "email_delivery",
                "data_flow",
                "audit_record",
                "account",
                "search",
                "analytics",
                "support",
                "export",
                "backup",
                "tombstone",
                "marketing",
                "cache",
            )
            if resource_id.casefold().startswith(f"{key}_")
        )
        system = {
            "account": "account_service",
            "search": "search_service",
            "analytics": "analytics_platform",
            "support": "support_platform",
            "export": "export_service",
            "data_flow": "integration_service",
            "backup": "backup_service",
            "audit_record": "security_service",
            "tombstone": "identity_service",
            "marketing": "marketing_service",
            "cache": "cache_service",
            "email_delivery": "email_delivery_service",
        }[prefix]
        start, end = max(0, match.start() - 240), min(len(text), match.end() + 240)
        snippet = text[start:end]
        if prefix == "support":
            category = "SUPPORT_ATTACHMENT" if "attachment" in text.casefold() else "SUPPORT_MESSAGE"
        else:
            category = _category(system, path_name, {"resource_id": resource_id})
        fields: dict[str, Any] = {
            "resource_id": resource_id,
            "record_type": category,
            "message_text": snippet,
        }
        result_match = re.search(
            r"\b(NOT_FOUND|IDENTIFIABLE|ANONYMIZED|ANONYMIZED|REDACTED|"
            r"ACTIVE|DISABLED|BLOCKED|FOUND|ABSENT)\b",
            snippet,
            re.IGNORECASE,
        )
        if result_match:
            fields["result"] = result_match.group(1)
        observation = _record_observation(
            fields,
            system,
            category.casefold(),
            evidence_id,
            captured_at,
            f"{system}:document",
            snippet,
        )
        if observation:
            observations.append(observation)
    return observations


def max_timestamp(left: str, right: str) -> str:
    left_dt, right_dt = parse_time(left), parse_time(right)
    if left_dt and right_dt:
        return left if left_dt >= right_dt else right
    return left or right


def _pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError as exc:
        raise RuntimeError(
            "PDF evidence requires pypdf. Install code/requirements.txt."
        ) from exc
    except Exception as exc:
        raise ValueError(f"Cannot extract PDF evidence {path}: {exc}") from exc


def _fallback_pdf_text(path: Path) -> str:
    data = path.read_bytes()
    chunks = re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S)
    streams: list[bytes] = []
    for chunk in chunks:
        try:
            streams.append(zlib.decompress(chunk))
        except zlib.error:
            streams.append(chunk)
    content = b"\n".join(streams)
    strings: list[str] = []
    for match in re.finditer(rb"\((?:\\.|[^\\)])*\)\s*Tj", content, re.S):
        raw = match.group(0).rsplit(b")", 1)[0][1:]
        raw = re.sub(rb"\\([()\\])", rb"\1", raw)
        raw = re.sub(rb"\\[nrt]", b" ", raw)
        strings.append(raw.decode("latin-1", errors="replace"))
    for match in re.finditer(rb"\[(.*?)\]\s*TJ", content, re.S):
        for raw in re.findall(rb"\((?:\\.|[^\\)])*\)", match.group(1), re.S):
            raw = raw[1:-1]
            raw = re.sub(rb"\\([()\\])", rb"\1", raw)
            strings.append(raw.decode("latin-1", errors="replace"))
    return "\n".join(strings)


def _tesseract_executable() -> str | None:
    configured = os.environ.get("TESSERACT_CMD", "").strip()
    if configured:
        if Path(configured).is_file():
            return configured
        resolved = shutil.which(configured)
        if resolved:
            return resolved
    executable = shutil.which("tesseract")
    if executable:
        return executable
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(variable)
        if not base:
            continue
        for folder in ("Tesseract-OCR", "Tessract_OCR"):
            candidate = Path(base) / folder / "tesseract.exe"
            if candidate.is_file():
                return str(candidate)
    return None


def load_evidence() -> list[Observation]:
    manifest = read_csv(DATASET / "evidence_files.csv")
    observations: list[Observation] = []
    for entry in manifest:
        path = DATASET / entry["file_path"]
        if not path.is_file():
            raise FileNotFoundError(f"Manifest evidence is missing: {path}")
        evidence_id = entry["file_id"]
        captured_at = entry["captured_at"]
        if path.suffix.casefold() == ".sql":
            observations.extend(_sql_observations(path, evidence_id, captured_at))
        elif path.suffix.casefold() == ".json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Cannot parse evidence JSON {path}: {exc}") from exc
            observations.extend(
                _json_observations(obj, evidence_id, captured_at, path.stem)
            )
        elif path.suffix.casefold() in {".log", ".txt"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            observations.extend(
                _text_observations(text, evidence_id, captured_at, path.stem)
            )
        elif path.suffix.casefold() == ".pdf":
            extracted = _pdf_text(path)
            observations.extend(
                _text_observations(
                    extracted, evidence_id, captured_at, path.stem
                )
            )
            observations.extend(
                _document_observations(extracted, evidence_id, captured_at, path.stem)
            )
        elif path.suffix.casefold() == ".png":
            executable = _tesseract_executable()
            if executable:
                result = subprocess.run(
                    [executable, str(path), "stdout"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    observations.extend(
                        _text_observations(
                            result.stdout, evidence_id, captured_at, path.stem
                        )
                    )
                    observations.extend(
                        _document_observations(
                            result.stdout, evidence_id, captured_at, path.stem
                        )
                    )
                else:
                    print(
                        f"Warning: image OCR failed for {path}: {result.stderr.strip()}",
                        file=sys.stderr,
                    )
    return observations


def build_identity_maps() -> tuple[
    dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]
]:
    identities = read_csv(DATASET / "user_identities.csv")
    audits = read_csv(DATASET / "user_audit_log.csv")
    email_to_users: dict[str, set[str]] = {}
    user_aliases: dict[str, set[str]] = {}
    email_to_users.setdefault("", set())
    for identity in identities:
        user_id = identity["user_id"]
        user_aliases.setdefault(user_id, set()).add(user_id.casefold())
        for key in ("email", "email_hash", "phone", "name"):
            value = normalized(identity.get(key))
            if value:
                user_aliases[user_id].add(value)
        email = normalized(identity.get("email"))
        if email:
            email_to_users.setdefault(email, set()).add(user_id)
    for audit in audits:
        user_id = audit["user_id"]
        value_key = audit["field_name"]
        if value_key not in {"email", "email_hash", "phone", "name"}:
            continue
        aliases = user_aliases.setdefault(user_id, {user_id.casefold()})
        for key in ("old_value", "new_value"):
            value = normalized(audit.get(key))
            if value:
                aliases.add(value)
                if value_key == "email":
                    email_to_users.setdefault(value, set()).add(user_id)
    return email_to_users, user_aliases, {}


def _extract_text_aliases(value: str, aliases: set[str]) -> set[str]:
    found: set[str] = set()
    lowered = value.casefold()
    for alias in aliases:
        if not alias or len(alias) < 5:
            continue
        if alias in lowered:
            if "@" in alias:
                pattern = rf"(?<![\w.+-]){re.escape(alias)}(?![\w.-])"
                if re.search(pattern, lowered):
                    found.add(alias)
            elif alias.startswith("+") or alias.replace(" ", "").isdigit():
                if alias in lowered:
                    found.add(alias)
    return found


def matches_identity(
    observation: Observation,
    user_id: str,
    aliases: set[str],
) -> bool:
    fields = observation.fields
    if any(normalized(fields.get(key)) == user_id.casefold() for key in REFERENCE_KEYS):
        return True
    for value in value_strings(fields):
        if normalized(value) in aliases:
            return True
    if any(
        normalized(fields.get(key)) == user_id.casefold()
        for key in ("lookup_key", "lookup_value", "correlation_key")
    ):
        return True
    textual_fields = {
        "message_text",
        "message_excerpt",
        "lookup_value",
        "query",
        "correlation_key",
        "details",
    }
    for key in textual_fields:
        value = fields.get(key)
        if value and _extract_text_aliases(str(value), aliases):
            return True
    return False


def _is_pii_for_identity(observation: Observation, aliases: set[str]) -> bool:
    fields = observation.fields
    for key in PII_KEYS:
        value = fields.get(key)
        if value is None or normalized(value) in {"", "null", "none", "redacted"}:
            continue
        if normalized(value) in aliases:
            return True
    for key in (
        "message_text",
        "message_excerpt",
        "details",
        "content",
        "correlation_key",
        "lookup_value",
    ):
        value = fields.get(key)
        if value and (
            normalized(value) in aliases
            or _extract_text_aliases(str(value), aliases)
        ):
            return True
    return False


def _text_state(observation: Observation, aliases: set[str]) -> str:
    fields = observation.fields
    if observation.category == "ACCOUNT_TOMBSTONE":
        return "PRESENT" if _is_pii_for_identity(observation, aliases) else "REDACTED"
    if observation.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        linked = any(
            normalized(fields.get(key)).startswith("user_")
            for key in REFERENCE_KEYS
        )
        return (
            "PRESENT"
            if linked
            or _is_pii_for_identity(observation, aliases)
            or normalized(fields.get("result")) == "identifiable"
            else "ANONYMIZED"
        )
    if observation.category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
        return (
            "PRESENT"
            if _is_pii_for_identity(observation, aliases)
            or normalized(fields.get("result")) in {"identifiable", "found"}
            else "REDACTED"
        )
    return observation.state


def _action_for(observation: Observation, aliases: set[str]) -> tuple[str, str, str] | None:
    category = observation.category
    state = _text_state(observation, aliases)
    if category == "DATA_FLOW":
        if state == "ACTIVE":
            return ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED")
        if state == "DISABLED":
            return None
    if category == "BACKUP_ARCHIVE":
        if state == "ACTIVE":
            return ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")
        if state == "BLOCKED":
            return None
    if category == "SECURITY_AUDIT_LOG":
        return None
    if category == "BACKUP_ARCHIVE":
        return None
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
        if state == "PRESENT":
            return ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED")
        if state == "REDACTED":
            return None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if state == "PRESENT":
            return ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")
        if state == "ANONYMIZED":
            return None
    if category in {
        "USER_PROFILE",
        "SECONDARY_IDENTIFIER",
        "SEARCH_INDEX_ENTRY",
        "CACHE_ENTRY",
        "SUPPORT_ATTACHMENT",
        "USER_EXPORT",
        "MARKETING_PROFILE",
    }:
        if state == "PRESENT":
            return ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT")
        if state == "ABSENT":
            return None
    return None


def _verification_for(observation: Observation, aliases: set[str]) -> tuple[str, str] | None:
    category = observation.category
    state = _text_state(observation, aliases)
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
                    "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE"}:
        if state == "ABSENT":
            return "VERIFY_RECORD_ABSENT", "ABSENT"
    if category == "SECURITY_AUDIT_LOG":
        return "VERIFY_RECORD_PRESENT", "PRESENT"
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"} and state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and state == "ANONYMIZED":
        return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if category == "DATA_FLOW" and state == "DISABLED":
        return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
    if category == "BACKUP_ARCHIVE" and state == "BLOCKED":
        return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
    return None


def _subject_id_for(request: dict[str, str], email_to_users: dict[str, set[str]]) -> str | None:
    matches = email_to_users.get(normalized(request.get("email")), set())
    if len(matches) == 1:
        return next(iter(matches))
    if len(matches) > 1:
        raise ValueError(f"Request email maps to multiple users: {request['case_id']}")
    return None


def _activity_linked_resources(
    user_id: str, aliases: set[str], audit_at: str
) -> set[str]:
    cutoff = parse_time(audit_at)
    linked: set[str] = set()
    for activity in read_csv(DATASET / "system_activity.csv"):
        if activity["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        event_time = parse_time(activity.get("event_time"))
        if cutoff and event_time and event_time > cutoff:
            continue
        details = activity.get("details", "")
        if user_id.casefold() in {
            token.casefold() for token in re.findall(r"\buser_\d+\b", details, re.I)
        } or _extract_text_aliases(details, aliases):
            resource_id = activity.get("resource_id", "").strip()
            if resource_id:
                linked.add(resource_id)
    return linked


def is_deletion_request(text: str) -> bool:
    value = normalized(text)
    if re.search(
        r"\b(?:do not|don't|not|never)\s+(?:request(?:ing)?|ask(?:ing)? for|"
        r"seek(?:ing)?)\s+(?:an?\s+)?(?:delet\w*|eras\w*|account closure)\b|"
        r"\bnot a deletion request\b|"
        r"\b(do not|don't|not|never)\s+(delete|erase|remove|close|cancel)\b",
        value,
    ):
        return False
    non_deletion = (
        r"\b(access|download|export|correct|correction|update|change|rectify|"
        r"opt[- ]?out|unsubscribe|marketing preferences|data portability)\b",
        r"\b(acc[eè]s|correcci[oó]n|actualizar|exportar|descargar|"
        r"optar por no recibir|dejar de recibir)\b",
        r"\b(acc[eè]s|rectification|corriger|modifier|t[eé]l[eé]charger|"
        r"exporter|ne plus recevoir)\b",
    )
    if any(token in value for token in ("削除", "消去", "삭제", "탈퇴")):
        return True
    if re.search(
        r"\b(account|profile|request)\b.{0,50}\b(deleted|removed|gone|erased)\b|"
        r"\b(deleted|removed|erased)\b.{0,40}\b(account|profile|request)\b",
        value,
    ):
        return True
    deletion = (
        r"\b(delet\w*|eras\w*|remov\w*|clos\w+\s+(?:the|my|this)\s+account|"
        r"account closure|account termination|purge|wipe)\b",
        r"\b(eliminar|eliminaci[oó]n|borrar|suprimir|cerrar mi cuenta)\b",
        r"\b(suppression|supprimer|effacer|fermer mon compte)\b",
        r"\b(l[oö]schen|entfernen|konto schlie[ßs]en)\b",
        r"\b(apagar|excluir|deletar|encerrar minha conta)\b",
        r"\b(삭제|탈퇴|계정.*삭제|消去|削除|アカウント.*削除)\b",
    )
    has_delete = any(re.search(pattern, value) for pattern in deletion)
    if any(re.search(pattern, value) for pattern in non_deletion) and not has_delete:
        return False
    return has_delete


def _step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def _latest_observations(
    observations: list[Observation], request: dict[str, str]
) -> list[Observation]:
    cutoff = parse_time(request.get("audit_at"))
    eligible = [
        obs
        for obs in observations
        if not cutoff
        or not parse_time(obs.available_at or obs.captured_at)
        or parse_time(obs.available_at or obs.captured_at) <= cutoff
    ]
    latest: dict[tuple[str, str, str], Observation] = {}
    state_priority = {
        "PRESENT": 6,
        "ACTIVE": 5,
        "ABSENT": 4,
        "REDACTED": 3,
        "ANONYMIZED": 2,
        "DISABLED": 1,
        "BLOCKED": 1,
    }
    for obs in eligible:
        key = (obs.system_id, obs.resource_id, obs.category)
        current = latest.get(key)
        obs_time, current_time = parse_time(obs.captured_at), parse_time(current.captured_at) if current else None
        if (
            current is None
            or (obs_time and (not current_time or obs_time > current_time))
            or (
                obs_time == current_time
                and state_priority.get(obs.state, 0)
                > state_priority.get(current.state, 0)
            )
        ):
            latest[key] = obs
    return sorted(
        latest.values(),
        key=lambda obs: (obs.system_id, obs.resource_id, obs.category, obs.evidence_id),
    )


def audit_request(
    request: dict[str, str],
    observations: list[Observation],
    email_to_users: dict[str, set[str]],
    user_aliases: dict[str, set[str]],
) -> tuple[str, list[dict[str, Any]]]:
    if not is_deletion_request(request.get("request_text", "")):
        return "NOT_APPLICABLE", []
    user_id = _subject_id_for(request, email_to_users)
    if not user_id:
        return "INCOMPLETE", []
    aliases = user_aliases.get(user_id, {user_id.casefold()})
    linked_resources = _activity_linked_resources(
        user_id, aliases, request.get("audit_at", "")
    )
    matched = [
        obs
        for obs in observations
        if matches_identity(obs, user_id, aliases)
        or obs.resource_id in linked_resources
    ]
    matched_latest = _latest_observations(matched, request)
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    has_violation = False
    has_account_proof = False
    seen_verifications: set[tuple[str, str, str, str]] = set()
    for obs in matched_latest:
        if obs.category == "USER_PROFILE" and obs.state == "ABSENT":
            has_account_proof = True
        elif obs.category == "ACCOUNT_TOMBSTONE" and _text_state(obs, aliases) in {"REDACTED", "PRESENT"}:
            has_account_proof = True
        action = _action_for(obs, aliases)
        if action:
            finding_op, remedy_op, verify_op = action
            has_violation = True
            finding_state = "ACTIVE" if finding_op in {
                "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK",
            } else "PRESENT"
            remedy_state = {
                "DISABLE_DATA_FLOW": "DISABLED",
                "BLOCK_RESTORE": "BLOCKED",
                "DELETE_RECORD": "ABSENT",
                "REDACT_RECORD": "REDACTED",
                "ANONYMIZE_RECORD": "ANONYMIZED",
            }[remedy_op]
            verify_state = remedy_state
            findings.append(
                _step(
                    "FINDING",
                    obs.system_id,
                    obs.resource_id,
                    finding_op,
                    finding_state,
                    obs.evidence_id,
                )
            )
            remediations.append(
                _step(
                    "REMEDIATION",
                    obs.system_id,
                    obs.resource_id,
                    remedy_op,
                    remedy_state,
                    "",
                )
            )
            key = (obs.system_id, obs.resource_id, verify_op, verify_state)
            if key not in seen_verifications:
                verifications.append(
                    _step(
                        "VERIFICATION",
                        obs.system_id,
                        obs.resource_id,
                        verify_op,
                        verify_state,
                        "",
                    )
                )
                seen_verifications.add(key)
        else:
            verification = _verification_for(obs, aliases)
            if verification:
                verify_op, verify_state = verification
                evidence_id = obs.evidence_id
                if has_violation:
                    evidence_id = ""
                key = (obs.system_id, obs.resource_id, verify_op, verify_state)
                if key not in seen_verifications:
                    verifications.append(
                        _step(
                            "VERIFICATION",
                            obs.system_id,
                            obs.resource_id,
                            verify_op,
                            verify_state,
                            evidence_id,
                        )
                    )
                    seen_verifications.add(key)
    if not has_violation and not has_account_proof:
        return "INCOMPLETE", []
    status = "INCOMPLETE" if has_violation else "COMPLETE"
    if status == "INCOMPLETE":
        for step in verifications:
            step["evidence_id"] = ""
        steps = findings + remediations + verifications
    else:
        steps = verifications
    steps.sort(
        key=lambda step: (
            PHASE_ORDER[step["phase"]],
            OPERATION_ORDER[step["operation"]],
            step["system_id"],
            step["resource_id"],
            step["evidence_id"],
        )
    )
    for number, step in enumerate(steps, 1):
        step["step_no"] = number
    return status, steps


def generate(
    requests_path: Path,
    output_path: Path,
    observations: list[Observation] | None = None,
) -> list[dict[str, str]]:
    requests = read_csv(requests_path)
    if observations is None:
        observations = load_evidence()
    email_to_users, user_aliases, _ = build_identity_maps()
    result: list[dict[str, str]] = []
    for request in requests:
        status, steps = audit_request(
            request, observations, email_to_users, user_aliases
        )
        result.append(
            {
                "case_id": request["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
            }
        )
    result.sort(key=lambda row: row["case_id"])
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DATASET / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    rows = generate(args.input, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
