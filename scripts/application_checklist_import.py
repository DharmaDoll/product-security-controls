"""Read and reconcile an organization application-security checklist safely."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Callable


SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
CONTROL_ID = re.compile(r"^PSB-[A-Z]+-[0-9]{3}$")
FORMULA_PREFIXES = ("=", "+", "-", "@")
PUBLICATIONS = {"public", "organization-only"}
DISPOSITIONS = {
    "implemented",
    "planned",
    "duplicate",
    "out-of-scope",
    "mapping-review-required",
}
RESPONSIBLE_ROLES = {
    "developer",
    "repository-admin",
    "ci-platform",
    "build-platform",
    "release-manager",
    "security",
    "incident-response",
    "shared",
}
RELATIONSHIPS = {
    "addresses",
    "supports",
    "detects",
    "mitigates",
    "verifies",
    "evidence-for",
    "related-to",
}
CONFIDENCE = {"low", "medium", "high"}
RECONCILIATION_HEADERS = [
    "source_id",
    "atomic_id",
    "atomic_wording",
    "disposition",
    "control_ids",
    "responsible_role",
    "verification_method",
    "expected_evidence",
    "framework_mappings",
    "notes",
]
PROFILE_HEADERS = [
    "Source Title",
    "Source Owner",
    "Source Version",
    "Source Review Date",
    "Source SHA-256",
    "Source Sheet",
    "Source Row ID",
    "Source Wording",
    "Source Category",
    "Atomic Row ID",
    "Atomic Wording",
    "Relationship",
    "Disposition",
    "Control IDs",
    "Responsible Role",
    "Verification Method",
    "Expected Evidence",
    "Framework Mappings",
    "Mapping Review Status",
    "Publication",
    "Notes",
]
PUBLIC_RECONCILIATION_HEADERS = [
    "Source Row ID",
    "Atomic Row ID",
    "Relationship",
    "Disposition",
    "Control IDs",
    "Framework Mappings",
    "Mapping Review Status",
    "Publication",
    "Notes",
]
MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_XLSX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ROWS = 10000
MAX_COLUMNS = 200


class ApplicationImportError(RuntimeError):
    """The source cannot be imported without weakening the contract."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ApplicationImportError(f"{label} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing:
        raise ApplicationImportError(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ApplicationImportError(f"{label} has unknown fields: {', '.join(sorted(unknown))}")


def _require_string(value: Any, label: str, maximum: int = 5000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApplicationImportError(f"{label} must be a non-empty string")
    if len(value) > maximum:
        raise ApplicationImportError(f"{label} exceeds {maximum} characters")
    if any(ord(character) < 32 and character not in "\t\r\n" for character in value):
        raise ApplicationImportError(f"{label} contains prohibited control characters")
    return value.strip()


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ApplicationImportError(f"cannot read {label}") from error
    if not value:
        raise ApplicationImportError(f"{label} is empty")
    if len(value) > MAX_SOURCE_BYTES:
        raise ApplicationImportError(f"{label} exceeds {MAX_SOURCE_BYTES} bytes")
    return value


def _resolve_reference(manifest_path: Path, value: Any, label: str) -> Path:
    rendered = _require_string(value, f"{label} path", 1000)
    relative = Path(rendered)
    if relative.is_absolute() or ".." in relative.parts:
        raise ApplicationImportError(f"{label} path escapes the manifest directory")
    root = manifest_path.parent.resolve()
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise ApplicationImportError(f"{label} path escapes the manifest directory")
    return resolved


def _check_formula(value: str, label: str) -> None:
    if value.lstrip().startswith(FORMULA_PREFIXES):
        raise ApplicationImportError(f"{label} contains a formula-like cell")


def _read_csv_table(raw: bytes, label: str) -> list[list[str]]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ApplicationImportError(f"{label} must be UTF-8 CSV") from error
    try:
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except csv.Error as error:
        raise ApplicationImportError(f"cannot parse {label} CSV") from error
    if not rows or not rows[0]:
        raise ApplicationImportError(f"{label} has no header")
    if len(rows) > MAX_ROWS + 1:
        raise ApplicationImportError(f"{label} exceeds {MAX_ROWS} data rows")
    width = len(rows[0])
    if width > MAX_COLUMNS:
        raise ApplicationImportError(f"{label} exceeds {MAX_COLUMNS} columns")
    for row_number, row in enumerate(rows, start=1):
        if len(row) != width:
            raise ApplicationImportError(f"{label} row {row_number} has an inconsistent column count")
        for column_number, value in enumerate(row, start=1):
            _check_formula(value, f"{label} row {row_number} column {column_number}")
    if len(rows) == 1:
        raise ApplicationImportError(f"{label} has no data rows")
    return rows


def _xlsx_column_index(reference: str) -> int:
    match = re.match(r"^([A-Z]+)[0-9]+$", reference)
    if not match:
        raise ApplicationImportError("XLSX cell reference is invalid")
    result = 0
    for character in match.group(1):
        result = result * 26 + ord(character) - 64
    if result > MAX_COLUMNS:
        raise ApplicationImportError(f"XLSX exceeds {MAX_COLUMNS} columns")
    return result


def _safe_zip_members(archive: zipfile.ZipFile) -> None:
    total = 0
    for info in archive.infolist():
        member = PurePosixPath(info.filename)
        if member.is_absolute() or ".." in member.parts:
            raise ApplicationImportError("XLSX contains an unsafe archive path")
        total += info.file_size
        lowered = info.filename.lower()
        if "vbaproject" in lowered or lowered.startswith("xl/externallinks/"):
            raise ApplicationImportError("XLSX macros and external links are prohibited")
    if total > MAX_XLSX_UNCOMPRESSED_BYTES:
        raise ApplicationImportError("XLSX uncompressed content exceeds the safety limit")


def _read_xlsx_table(raw: bytes, sheet_name: str, label: str) -> list[list[str]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as error:
        raise ApplicationImportError(f"cannot parse {label} XLSX") from error
    with archive:
        _safe_zip_members(archive)
        try:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        except (KeyError, ET.ParseError) as error:
            raise ApplicationImportError(f"{label} XLSX workbook metadata is malformed") from error
        main_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        rel_doc_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        package_rel_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
        selected_id = None
        for sheet in workbook.findall(f".//{{{main_ns}}}sheet"):
            if sheet.get("name") == sheet_name:
                selected_id = sheet.get(f"{{{rel_doc_ns}}}id")
                break
        if selected_id is None:
            raise ApplicationImportError(f"{label} XLSX sheet {sheet_name!r} was not found")
        target = None
        for relationship in relationships.findall(f"{{{package_rel_ns}}}Relationship"):
            if relationship.get("Id") == selected_id:
                target = relationship.get("Target")
                break
        if not target:
            raise ApplicationImportError(f"{label} XLSX sheet relationship is missing")
        target_path = PurePosixPath(target.lstrip("/"))
        if target_path.parts and target_path.parts[0] == "xl":
            sheet_path = target_path
        else:
            sheet_path = PurePosixPath("xl") / target_path
        if ".." in sheet_path.parts:
            raise ApplicationImportError(f"{label} XLSX sheet path is unsafe")

        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            try:
                shared = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            except ET.ParseError as error:
                raise ApplicationImportError(f"{label} XLSX shared strings are malformed") from error
            for item in shared.findall(f"{{{main_ns}}}si"):
                shared_strings.append("".join(node.text or "" for node in item.iter(f"{{{main_ns}}}t")))
        try:
            worksheet = ET.fromstring(archive.read(str(sheet_path)))
        except (KeyError, ET.ParseError) as error:
            raise ApplicationImportError(f"{label} XLSX worksheet is malformed") from error
        rows: list[list[str]] = []
        for row_element in worksheet.findall(f".//{{{main_ns}}}row"):
            if len(rows) > MAX_ROWS:
                raise ApplicationImportError(f"{label} exceeds {MAX_ROWS} data rows")
            values: dict[int, str] = {}
            for cell in row_element.findall(f"{{{main_ns}}}c"):
                if cell.find(f"{{{main_ns}}}f") is not None:
                    raise ApplicationImportError(f"{label} contains an XLSX formula cell")
                reference = cell.get("r")
                if not reference:
                    raise ApplicationImportError(f"{label} contains a cell without a reference")
                index = _xlsx_column_index(reference)
                cell_type = cell.get("t")
                if cell_type == "inlineStr":
                    value = "".join(node.text or "" for node in cell.iter(f"{{{main_ns}}}t"))
                else:
                    node = cell.find(f"{{{main_ns}}}v")
                    value = node.text if node is not None and node.text is not None else ""
                    if cell_type == "s":
                        try:
                            value = shared_strings[int(value)]
                        except (ValueError, IndexError) as error:
                            raise ApplicationImportError(f"{label} has an invalid shared-string index") from error
                _check_formula(value, f"{label} cell {reference}")
                values[index] = value
            if values:
                rows.append([values.get(index, "") for index in range(1, max(values) + 1)])
        if not rows or len(rows) == 1:
            raise ApplicationImportError(f"{label} has no data rows")
        width = len(rows[0])
        if not width:
            raise ApplicationImportError(f"{label} has no header")
        for row_number, row in enumerate(rows, start=1):
            if len(row) < width:
                row.extend([""] * (width - len(row)))
            if len(row) != width:
                raise ApplicationImportError(f"{label} row {row_number} has an inconsistent column count")
        return rows


def _table_to_records(
    table: list[list[str]], expected_headers: list[str], label: str
) -> list[dict[str, str]]:
    headers = [header.strip() for header in table[0]]
    if len(headers) != len(set(headers)):
        raise ApplicationImportError(f"{label} contains duplicate headers")
    if set(headers) != set(expected_headers):
        missing = set(expected_headers) - set(headers)
        unknown = set(headers) - set(expected_headers)
        details = []
        if missing:
            details.append(f"missing {', '.join(sorted(missing))}")
        if unknown:
            details.append(f"unknown {', '.join(sorted(unknown))}")
        raise ApplicationImportError(f"{label} columns do not match the manifest: {'; '.join(details)}")
    records = []
    for values in table[1:]:
        if not any(value.strip() for value in values):
            raise ApplicationImportError(f"{label} contains a blank data row")
        records.append(dict(zip(headers, values, strict=True)))
    return records


def _validate_manifest(manifest_path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_bytes(manifest_path, "application checklist manifest")
    try:
        manifest = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ApplicationImportError("cannot parse application checklist manifest") from error
    manifest = _require_object(manifest, "manifest")
    _require_exact_keys(manifest, {"schema", "source", "input", "columns", "reconciliation"}, "manifest")
    if manifest.get("schema") != "psb-application-checklist-source/v1.0":
        raise ApplicationImportError("unsupported application checklist manifest schema")
    source = _require_object(manifest["source"], "manifest.source")
    _require_exact_keys(source, {"title", "owner", "version", "review_date"}, "manifest.source")
    for key in ("title", "owner", "version"):
        _require_string(source.get(key), f"manifest.source.{key}", 500)
    review_date = _require_string(source.get("review_date"), "manifest.source.review_date", 20)
    try:
        date.fromisoformat(review_date)
    except ValueError as error:
        raise ApplicationImportError("manifest.source.review_date must be an ISO date") from error
    input_config = _require_object(manifest["input"], "manifest.input")
    _require_exact_keys(input_config, {"path", "format", "sheet", "sha256"}, "manifest.input")
    if input_config.get("format") not in {"csv", "xlsx"}:
        raise ApplicationImportError("manifest.input.format must be csv or xlsx")
    _require_string(input_config.get("sheet"), "manifest.input.sheet", 100)
    if input_config["format"] == "csv" and input_config["sheet"] != "CSV":
        raise ApplicationImportError("CSV input sheet must be named CSV")
    if not isinstance(input_config.get("sha256"), str) or not SHA256.fullmatch(input_config["sha256"]):
        raise ApplicationImportError("manifest.input.sha256 is invalid")
    columns = _require_object(manifest["columns"], "manifest.columns")
    _require_exact_keys(columns, {"source_id", "wording", "category", "publication"}, "manifest.columns")
    column_names = [_require_string(columns.get(key), f"manifest.columns.{key}", 200) for key in columns]
    if len(column_names) != len(set(column_names)):
        raise ApplicationImportError("manifest.columns contains duplicate source headers")
    reconciliation = _require_object(manifest["reconciliation"], "manifest.reconciliation")
    _require_exact_keys(reconciliation, {"path", "format", "sha256"}, "manifest.reconciliation")
    if reconciliation.get("format") != "csv":
        raise ApplicationImportError("manifest.reconciliation.format must be csv")
    if not isinstance(reconciliation.get("sha256"), str) or not SHA256.fullmatch(reconciliation["sha256"]):
        raise ApplicationImportError("manifest.reconciliation.sha256 is invalid")
    return manifest, raw


def _parse_mappings(
    value: str,
    registries: dict[str, dict[str, Any]],
    label: str,
) -> tuple[str, str]:
    rendered = value.strip()
    if not rendered:
        return "", "unmapped"
    normalized = []
    for raw_mapping in rendered.split(";"):
        parts = [part.strip() for part in raw_mapping.split("|")]
        if len(parts) != 5:
            raise ApplicationImportError(f"{label} framework mapping must have five pipe-separated fields")
        framework, version, identifier, relationship, confidence = parts
        registry = registries.get(framework)
        if not registry:
            raise ApplicationImportError(f"{label} references unknown framework {framework}")
        if version != registry.get("mapping_version"):
            raise ApplicationImportError(f"{label} references unsupported {framework} version")
        if identifier not in {entry["id"] for entry in registry.get("entries", [])}:
            raise ApplicationImportError(f"{label} references unknown {framework} identifier {identifier}")
        if relationship not in RELATIONSHIPS or confidence not in CONFIDENCE:
            raise ApplicationImportError(f"{label} mapping relationship or confidence is invalid")
        normalized.append(" | ".join(parts))
    return "; ".join(normalized), "reviewed"


def load_application_profile(
    manifest_path: Path,
    repository_root: Path,
    registries: dict[str, dict[str, Any]],
    known_control_ids: set[str],
) -> dict[str, Any]:
    if not manifest_path.exists():
        return {
            "status": "INPUT_REQUIRED",
            "status_document": {
                "schema": "psb-application-checklist-import-status/v1.0",
                "status": "INPUT_REQUIRED",
                "manifest": str(manifest_path.relative_to(repository_root)),
                "message": "No organization application vulnerability assessment source manifest is present; no empty checklist was generated.",
                "required_input": [
                    "source title owner version and review date",
                    "source CSV or XLSX with exact SHA-256 and column semantics",
                    "reconciliation CSV with one disposition for every source row",
                ],
            },
        }

    manifest, manifest_raw = _validate_manifest(manifest_path)
    input_config = manifest["input"]
    source_path = _resolve_reference(manifest_path, input_config["path"], "source input")
    source_raw = _read_bytes(source_path, "application checklist source")
    if sha256_bytes(source_raw) != input_config["sha256"]:
        raise ApplicationImportError("application checklist source SHA-256 does not match manifest")
    if input_config["format"] == "csv":
        source_table = _read_csv_table(source_raw, "application checklist source")
    else:
        source_table = _read_xlsx_table(source_raw, input_config["sheet"], "application checklist source")
    columns = manifest["columns"]
    source_records_raw = _table_to_records(
        source_table,
        [columns["source_id"], columns["wording"], columns["category"], columns["publication"]],
        "application checklist source",
    )
    source_records: dict[str, dict[str, str]] = {}
    for index, raw_record in enumerate(source_records_raw, start=2):
        source_id = _require_string(raw_record[columns["source_id"]], f"source row {index} ID", 128)
        if not SOURCE_ID.fullmatch(source_id):
            raise ApplicationImportError(f"source row {index} ID has unsupported characters")
        if source_id in source_records:
            raise ApplicationImportError(f"duplicate source row ID {source_id}")
        wording = _require_string(raw_record[columns["wording"]], f"source row {source_id} wording")
        category = _require_string(raw_record[columns["category"]], f"source row {source_id} category", 200)
        publication = _require_string(raw_record[columns["publication"]], f"source row {source_id} publication", 30)
        if publication not in PUBLICATIONS:
            raise ApplicationImportError(f"source row {source_id} publication is unsupported")
        source_records[source_id] = {
            "source_id": source_id,
            "wording": wording,
            "category": category,
            "publication": publication,
        }

    reconciliation_config = manifest["reconciliation"]
    reconciliation_path = _resolve_reference(manifest_path, reconciliation_config["path"], "reconciliation")
    reconciliation_raw = _read_bytes(reconciliation_path, "application checklist reconciliation")
    if sha256_bytes(reconciliation_raw) != reconciliation_config["sha256"]:
        raise ApplicationImportError("application checklist reconciliation SHA-256 does not match manifest")
    reconciliation_records = _table_to_records(
        _read_csv_table(reconciliation_raw, "application checklist reconciliation"),
        RECONCILIATION_HEADERS,
        "application checklist reconciliation",
    )
    by_source: dict[str, list[dict[str, str]]] = {}
    atomic_ids: set[str] = set()
    for index, record in enumerate(reconciliation_records, start=2):
        source_id = _require_string(record["source_id"], f"reconciliation row {index} source_id", 128)
        if source_id not in source_records:
            raise ApplicationImportError(f"reconciliation references unknown source row {source_id}")
        atomic_id = _require_string(record["atomic_id"], f"reconciliation row {index} atomic_id", 128)
        if not SOURCE_ID.fullmatch(atomic_id) or atomic_id in atomic_ids:
            raise ApplicationImportError(f"reconciliation atomic ID {atomic_id} is invalid or duplicated")
        atomic_ids.add(atomic_id)
        atomic_wording = _require_string(record["atomic_wording"], f"reconciliation row {atomic_id} atomic wording")
        disposition = _require_string(record["disposition"], f"reconciliation row {atomic_id} disposition", 50)
        if disposition not in DISPOSITIONS:
            raise ApplicationImportError(f"reconciliation row {atomic_id} disposition is unsupported")
        controls = [item.strip() for item in record["control_ids"].split(";") if item.strip()]
        if any(not CONTROL_ID.fullmatch(control_id) for control_id in controls):
            raise ApplicationImportError(f"reconciliation row {atomic_id} has an invalid control ID")
        if disposition == "implemented" and (not controls or any(control_id not in known_control_ids for control_id in controls)):
            raise ApplicationImportError(f"reconciliation row {atomic_id} implemented controls are missing from the catalog")
        if disposition == "duplicate" and not controls:
            raise ApplicationImportError(f"reconciliation row {atomic_id} duplicate disposition lacks its owner control")
        responsible_role = _require_string(record["responsible_role"], f"reconciliation row {atomic_id} responsible role", 50)
        if responsible_role not in RESPONSIBLE_ROLES:
            raise ApplicationImportError(f"reconciliation row {atomic_id} responsible role is unsupported")
        verification = _require_string(record["verification_method"], f"reconciliation row {atomic_id} verification method")
        evidence = _require_string(record["expected_evidence"], f"reconciliation row {atomic_id} expected evidence")
        mappings, mapping_status = _parse_mappings(
            record["framework_mappings"], registries, f"reconciliation row {atomic_id}"
        )
        if mapping_status == "unmapped" and disposition not in {"mapping-review-required", "out-of-scope"}:
            raise ApplicationImportError(f"reconciliation row {atomic_id} needs a reviewed mapping or mapping-review-required disposition")
        notes = record["notes"].strip()
        if disposition == "out-of-scope" and not notes:
            raise ApplicationImportError(f"reconciliation row {atomic_id} out-of-scope disposition requires notes")
        normalized = {
            "source_id": source_id,
            "atomic_id": atomic_id,
            "atomic_wording": atomic_wording,
            "disposition": disposition,
            "control_ids": "; ".join(controls),
            "responsible_role": responsible_role,
            "verification_method": verification,
            "expected_evidence": evidence,
            "framework_mappings": mappings,
            "mapping_status": mapping_status,
            "notes": notes,
        }
        by_source.setdefault(source_id, []).append(normalized)
    missing_sources = set(source_records) - set(by_source)
    if missing_sources:
        raise ApplicationImportError(f"source rows lack reconciliation: {', '.join(sorted(missing_sources))}")

    source_meta = manifest["source"]
    profile_rows: list[dict[str, str]] = []
    public_reconciliation: list[dict[str, str]] = []
    organization_only_count = 0
    for source_id in sorted(source_records):
        source = source_records[source_id]
        reconciliations = sorted(by_source[source_id], key=lambda item: item["atomic_id"])
        relationship = "split-from" if len(reconciliations) > 1 else "same-as-source"
        if source["publication"] == "organization-only":
            organization_only_count += 1
            redacted_id = "REDACTED-" + sha256_bytes(source_id.encode("utf-8"))[:12]
            public_reconciliation.append(
                {
                    "Source Row ID": redacted_id,
                    "Atomic Row ID": "NOT-EXPORTED",
                    "Relationship": "organization-only",
                    "Disposition": "organization-only-not-exported",
                    "Control IDs": "",
                    "Framework Mappings": "",
                    "Mapping Review Status": "not-exported",
                    "Publication": "organization-only",
                    "Notes": "Original row remains recoverable only from the organization-owned source and reconciliation files.",
                }
            )
            continue
        for reconciliation in reconciliations:
            profile_rows.append(
                {
                    "Source Title": source_meta["title"],
                    "Source Owner": source_meta["owner"],
                    "Source Version": source_meta["version"],
                    "Source Review Date": source_meta["review_date"],
                    "Source SHA-256": input_config["sha256"],
                    "Source Sheet": input_config["sheet"],
                    "Source Row ID": source_id,
                    "Source Wording": source["wording"],
                    "Source Category": source["category"],
                    "Atomic Row ID": reconciliation["atomic_id"],
                    "Atomic Wording": reconciliation["atomic_wording"],
                    "Relationship": relationship,
                    "Disposition": reconciliation["disposition"],
                    "Control IDs": reconciliation["control_ids"],
                    "Responsible Role": reconciliation["responsible_role"],
                    "Verification Method": reconciliation["verification_method"],
                    "Expected Evidence": reconciliation["expected_evidence"],
                    "Framework Mappings": reconciliation["framework_mappings"],
                    "Mapping Review Status": reconciliation["mapping_status"],
                    "Publication": "public",
                    "Notes": reconciliation["notes"],
                }
            )
            public_reconciliation.append(
                {
                    "Source Row ID": source_id,
                    "Atomic Row ID": reconciliation["atomic_id"],
                    "Relationship": relationship,
                    "Disposition": reconciliation["disposition"],
                    "Control IDs": reconciliation["control_ids"],
                    "Framework Mappings": reconciliation["framework_mappings"],
                    "Mapping Review Status": reconciliation["mapping_status"],
                    "Publication": "public",
                    "Notes": reconciliation["notes"],
                }
            )
    status_document = {
        "schema": "psb-application-checklist-import-status/v1.0",
        "status": "GENERATED",
        "manifest_sha256": sha256_bytes(manifest_raw),
        "source_sha256": input_config["sha256"],
        "reconciliation_sha256": reconciliation_config["sha256"],
        "source_title": source_meta["title"],
        "source_owner": source_meta["owner"],
        "source_version": source_meta["version"],
        "source_review_date": source_meta["review_date"],
        "source_rows": len(source_records),
        "atomic_rows": len(atomic_ids),
        "public_atomic_rows": len(profile_rows),
        "organization_only_source_rows": organization_only_count,
    }
    return {
        "status": "GENERATED",
        "status_document": status_document,
        "profile_rows": profile_rows,
        "reconciliation_rows": public_reconciliation,
    }


def _csv_safe(value: Any) -> str:
    rendered = str(value)
    return "'" + rendered if rendered.lstrip().startswith(FORMULA_PREFIXES) else rendered


def _write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({header: _csv_safe(row.get(header, "")) for header in headers})


def write_application_profile(
    output: Path,
    result: dict[str, Any],
    write_xlsx: Callable[[Path, list[tuple[str, list[str], list[list[str]]]]], None],
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name in ("profile.csv", "reconciliation.csv", "application-vulnerability-assessment.xlsx"):
        candidate = output / name
        if candidate.exists():
            candidate.unlink()
    (output / "status.json").write_text(
        json.dumps(result["status_document"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if result["status"] != "GENERATED":
        return
    profile_rows = result["profile_rows"]
    reconciliation_rows = result["reconciliation_rows"]
    _write_csv(output / "profile.csv", PROFILE_HEADERS, profile_rows)
    _write_csv(output / "reconciliation.csv", PUBLIC_RECONCILIATION_HEADERS, reconciliation_rows)
    readme_rows = [
        ["Purpose", "Source-preserving application vulnerability assessment profile; generated, not manually edited."],
        ["Source wording", "Public original wording is preserved. Organization-only wording is never exported."],
        ["Relationship", "same-as-source is one-to-one; split-from is a traceable one-to-many atomic split."],
        ["Disposition", "implemented, planned, duplicate, out-of-scope, or mapping-review-required."],
        ["Mappings", "Only exact reviewed registry identifiers are exported; relationships are not compliance claims."],
        ["Assessment", "Blank assessment fields belong in a copied organization-owned workbook, not this source profile."],
    ]
    profile_table = [[row.get(header, "") for header in PROFILE_HEADERS] for row in profile_rows]
    reconciliation_table = [
        [row.get(header, "") for header in PUBLIC_RECONCILIATION_HEADERS]
        for row in reconciliation_rows
    ]
    write_xlsx(
        output / "application-vulnerability-assessment.xlsx",
        [
            ("README", ["Field", "Guidance"], readme_rows),
            ("Application Profile", PROFILE_HEADERS, profile_table),
            ("Reconciliation", PUBLIC_RECONCILIATION_HEADERS, reconciliation_table),
        ],
    )
