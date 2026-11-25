#!/usr/bin/env python3
"""Scan the container images listed in images.yml with trivy and grype.

"scan" prints a CVE summary, "upload" also stores the results in the
DynamoDB table read by the dashboard (web/).

The upload needs AWS credentials allowed to write to the table (GitHub
Actions: OIDC role, locally e.g. AWS_PROFILE=my-aws). Optional environment
variables:
  AWS_REGION      Region of the table (default: eu-central-1)
  DYNAMODB_TABLE  Table name (default: container-image-scans)
  IMAGES_FILE     Image list (default: images.yml in the repository root)
  GITHUB_STEP_SUMMARY  Markdown summary file (set by GitHub Actions)
"""

import argparse
import json
import os

# docker / trivy / grype run with fixed arguments, without a shell
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import yaml
from boto3.dynamodb.conditions import Key
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

REPO_ROOT = Path(__file__).resolve().parent.parent
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
# DynamoDB TTL deletes the items (for free) two years after the scan
TTL_SECONDS = 2 * 365 * 24 * 60 * 60

CVE = dict[str, str]


@dataclass(frozen=True)
class Image:
    """One image of images.yml: group -> images -> vendor -> image."""

    group: str
    group_description: str
    vendor: str
    image: str
    description: str


def load_images(path: Path) -> list[Image]:
    """Read images.yml (group -> description + images -> vendor -> ...)."""
    groups = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        Image(
            group=group,
            group_description=data.get("description") or "",
            vendor=vendor,
            image=entry["image"],
            description=entry.get("description") or "",
        )
        for group, data in groups.items()
        for vendor, entry in (data.get("images") or {}).items()
    ]


def normalize_severity(value: str | None) -> str:
    """Map a scanner severity to CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN."""
    severity = (value or "").upper()
    if severity == "NEGLIGIBLE":  # grype only
        return "LOW"
    return severity if severity in SEVERITIES else "UNKNOWN"


def unique(cves: Iterable[CVE]) -> list[CVE]:
    """Keep one entry per CVE and package (sorted).

    Both scanners report a CVE once for every affected package, sometimes
    more than once (e.g. one package found in several paths).
    """
    found: dict[tuple[str, str], CVE] = {}
    for cve in cves:
        found.setdefault((cve["cve_id"], cve["package_name"]), cve)
    return [found[key] for key in sorted(found)]


def trivy_cves(report: dict[str, Any]) -> list[CVE]:
    """Map a `trivy image --format json` report to CVE entries."""
    return unique(
        {
            "cve_id": vuln["VulnerabilityID"],
            "severity": normalize_severity(vuln.get("Severity")),
            "description": vuln.get("Title") or vuln.get("Description") or "",
            "url": vuln.get("PrimaryURL") or "",
            "package_name": vuln.get("PkgName") or "",
            "installed_version": vuln.get("InstalledVersion") or "",
            "fixed_version": vuln.get("FixedVersion") or "",
        }
        for result in report.get("Results") or []
        for vuln in result.get("Vulnerabilities") or []
    )


def grype_cves(report: dict[str, Any]) -> list[CVE]:
    """Map a `grype --by-cve -o json` report to CVE entries."""
    entries = []
    for match in report.get("matches") or []:
        vuln = match["vulnerability"]
        related = match.get("relatedVulnerabilities") or [{}]
        entries.append(
            {
                "cve_id": vuln["id"],
                "severity": normalize_severity(vuln.get("severity")),
                "description": vuln.get("description")
                or related[0].get("description")
                or "",
                "url": vuln.get("dataSource") or "",
                "package_name": match["artifact"]["name"],
                "installed_version": match["artifact"]["version"],
                "fixed_version": ", ".join(
                    (vuln.get("fix") or {}).get("versions") or []
                ),
            }
        )
    return unique(entries)


def top_fixable(cves: list[CVE], limit: int = 8) -> list[CVE]:
    """The worst CVEs with a fixed version (for the dashboard popup).

    Stored in the LATEST item, so the popup reads no CVE partition.
    """
    order = (*SEVERITIES, "UNKNOWN")
    fixable = sorted(
        (cve for cve in cves if cve["fixed_version"]),
        key=lambda cve: (
            order.index(cve["severity"]),
            cve["cve_id"],
            cve["package_name"],
        ),
    )
    keep = (
        "cve_id",
        "severity",
        "package_name",
        "installed_version",
        "fixed_version",
    )
    return [{key: cve[key] for key in keep} for cve in fixable[:limit]]


def severity_counts(cves: list[CVE]) -> dict[str, int]:
    """Count the CVEs: total, per severity and fixable (fix available)."""
    counts = {"total": len(cves)}
    for severity in SEVERITIES:
        counts[severity.lower()] = sum(
            1 for cve in cves if cve["severity"] == severity
        )
    counts["fixable"] = sum(1 for cve in cves if cve["fixed_version"])
    return counts


def scan_items(
    image: Image,
    scanner: str,
    info: dict[str, Any],
    cves: list[CVE],
    scanned_at: str,
) -> list[dict[str, Any]]:
    """Build the DynamoDB items of one scan: CVEs, HISTORY, LATEST last.

    The CVEs get their own partition, HISTORY and LATEST point to it (see
    write_items()). LATEST is keyed by group + vendor (not the image name),
    so a new image of the same vendor replaces the old dashboard row.
    HISTORY#<group> keeps the summary of every scan of the group, sorted
    by time - the dashboard charts read it.
    """
    expires_at = int(datetime.fromisoformat(scanned_at).timestamp()) + (
        TTL_SECONDS
    )
    key = f"{image.group}#{image.vendor}#{scanner}"
    cves_pk = f"CVES#{key}#{scanned_at}"
    counts = severity_counts(cves)
    items: list[dict[str, Any]] = [
        {
            "pk": cves_pk,
            "sk": f"{cve['cve_id']}#{cve['package_name']}",
            **cve,
            "expires_at": expires_at,
        }
        for cve in cves
    ]
    summary = {
        "group": image.group,
        "vendor": image.vendor,
        "image": image.image,
        "scanner": scanner,
        "scanner_version": info["version"],
        "scanner_db": info["db"],
        "image_digest": info["digest"],
        "image_size": info["size"],
        "image_created": info["created"],
        "scanned_at": scanned_at,
        "cves_pk": cves_pk,
        **{f"cve_{name}": count for name, count in counts.items()},
        "expires_at": expires_at,
    }
    items.append(
        {
            "pk": f"HISTORY#{image.group}",
            "sk": f"{scanned_at}#{image.vendor}#{scanner}",
            **summary,
        }
    )
    items.append(
        {
            "pk": "LATEST",
            "sk": key,
            **summary,
            "group_description": image.group_description,
            "image_description": image.description,
            "top_fixable": top_fixable(cves),
        }
    )
    return items


def lifecycle_items(
    latest: dict[str, Any], previous: list[dict[str, Any]], cves: list[CVE]
) -> list[dict[str, Any]]:
    """Changed LIFECYCLE items of one image + scanner after a scan.

    LIFECYCLE#<group>#<vendor>#<scanner> has one item per CVE + package
    ever found: first_seen (first scan with it), fix_seen (first scan with
    a fixed version) and removed_at (first scan without it). Only new and
    changed items are returned - most scans write none. A CVE found again
    after its removal starts a new lifecycle.
    """
    pk = f"LIFECYCLE#{latest['sk']}"
    scanned_at = latest["scanned_at"]
    expires_at = latest["expires_at"]
    known = {item["sk"]: item for item in previous}
    current = {f"{cve['cve_id']}#{cve['package_name']}": cve for cve in cves}
    changed: list[dict[str, Any]] = []
    for sk, cve in current.items():
        old = known.get(sk)
        if old is None or "removed_at" in old:
            item = {
                "pk": pk,
                "sk": sk,
                "cve_id": cve["cve_id"],
                "package_name": cve["package_name"],
                "severity": cve["severity"],
                "installed_version": cve["installed_version"],
                "fixed_version": cve["fixed_version"],
                "first_seen": scanned_at,
            }
            if cve["fixed_version"]:
                item["fix_seen"] = scanned_at
        elif cve["fixed_version"] and "fix_seen" not in old:
            item = {
                **old,
                "fixed_version": cve["fixed_version"],
                "fix_seen": scanned_at,
            }
        else:
            continue
        # shortcut: unchanged open CVEs keep their TTL, after two years
        # they restart as new - refresh expires_at if that matters
        changed.append({**item, "expires_at": expires_at})
    changed.extend(
        {**old, "removed_at": scanned_at, "expires_at": expires_at}
        for sk, old in known.items()
        if sk not in current and "removed_at" not in old
    )
    return changed


def write_items(table: Any, items: list[dict[str, Any]]) -> None:
    """Write the CVEs of one scan, then its HISTORY and LATEST items.

    batch_writer() sends 25 items per request and resends throttled
    (unprocessed) items - at the end of its queue, so out of order. HISTORY
    and LATEST are written only after all CVEs are stored: the dashboard
    never sees a half-written scan. The client retries throttling errors
    (adaptive retry mode, see main()).
    """
    *cves, history, latest = items
    with table.batch_writer() as batch:
        for item in cves:
            batch.put_item(Item=item)
    table.put_item(Item=history)
    table.put_item(Item=latest)


def write_day(table: Any, scanned_at: str) -> None:
    """Add the day of a run to the DAYS partition (sk = YYYY-MM-DD).

    The dashboard lists the days with scans from it (no Scan needed).
    """
    table.put_item(
        Item={
            "pk": "DAYS",
            "sk": scanned_at[:10],
            "expires_at": int(datetime.fromisoformat(scanned_at).timestamp())
            + TTL_SECONDS,
        }
    )


def query_partition(table: Any, pk: str) -> list[dict[str, Any]]:
    """All items of one partition (Query returns max. 1 MB per page)."""
    kwargs: dict[str, Any] = {"KeyConditionExpression": Key("pk").eq(pk)}
    items: list[dict[str, Any]] = []
    while True:
        page = table.query(**kwargs)
        items.extend(page.get("Items") or [])
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def upload(table: Any, items: list[dict[str, Any]], cves: list[CVE]) -> None:
    """Write one scan (write_items()), then its CVE lifecycle changes."""
    latest = items[-1]
    previous = query_partition(table, f"LIFECYCLE#{latest['sk']}")
    write_items(table, items)
    with table.batch_writer() as batch:
        for item in lifecycle_items(latest, previous, cves):
            batch.put_item(Item=item)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a command (no shell), capture its output."""
    return subprocess.run(  # nosec B603
        command, capture_output=True, text=True, check=False
    )


def read_report(path: Path) -> dict[str, Any]:
    """Read a scanner JSON report ({} for an empty or invalid file)."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    return report if isinstance(report, dict) else {}


def image_metadata(image: str) -> dict[str, Any]:
    """Digest (sha256:... or "unknown"), size and creation of a pulled image.

    size: uncompressed bytes (0 = unknown), created: ISO date ("" when
    unknown, reproducible builds use 1970-01-01).
    """
    result = run(
        ["docker", "image", "inspect", "--format", "{{json .}}", image]
    )
    try:
        data = json.loads(result.stdout) if result.returncode == 0 else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    digest = str((data.get("RepoDigests") or [""])[0]).rpartition("@")[2]
    return {
        "digest": digest or "unknown",
        "size": int(data.get("Size") or 0),
        "created": str(data.get("Created") or ""),
    }


def scanner_info() -> dict[str, dict[str, str]]:
    """Versions and vulnerability database dates of trivy and grype."""
    trivy = json.loads(run(["trivy", "version", "--format", "json"]).stdout)
    grype = json.loads(run(["grype", "version", "-o", "json"]).stdout)
    grype_db = json.loads(run(["grype", "db", "status", "-o", "json"]).stdout)
    return {
        "trivy": {
            "version": trivy.get("Version", ""),
            "db": (trivy.get("VulnerabilityDB") or {}).get("UpdatedAt", ""),
        },
        "grype": {
            "version": grype.get("version", ""),
            "db": grype_db.get("built", ""),
        },
    }


def scan(image: str, scanner: str, workdir: Path) -> list[CVE] | None:
    """Scan one image with one scanner (None when the scan failed).

    The scanners exit 0 when they find CVEs - a non-zero exit is a failure.
    A missing or invalid report is a failure too, not "0 CVEs": every trivy
    report has "SchemaVersion", every grype report "matches" (also empty).
    """
    report = workdir / f"{scanner}.json"
    if scanner == "trivy":
        command = ["trivy", "image", image, "--scanners", "vuln"]
        command += ["--skip-db-update", "--format", "json"]
        command += ["--output", str(report)]
    else:
        command = ["grype", image, "--by-cve", "--output", "json"]
        command += ["--file", str(report)]
    result = run(command)
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        return None
    report_data = read_report(report)
    if scanner == "trivy" and "SchemaVersion" in report_data:
        return trivy_cves(report_data)
    if scanner == "grype" and "matches" in report_data:
        return grype_cves(report_data)
    print(f"  {scanner} wrote no valid report: {report}", file=sys.stderr)
    return None


def summary_line(scanner: str, cves: list[CVE] | None) -> str:
    """One line CVE summary of a scan."""
    if cves is None:
        return f"❌ {scanner}: scan failed, not uploaded"
    counts = severity_counts(cves)
    if not counts["total"]:
        return f"✅ {scanner}: no CVEs found"
    return (
        f"⚠️ {scanner:<6} {counts['total']:5} total  ("
        f" 🔴 C:{counts['critical']:<5} 🟠 H:{counts['high']:<5}"
        f" 🟡 M:{counts['medium']:<5} 🔵 L:{counts['low']:<5})"
    )


def print_summary(
    rows: list[tuple[str, str, dict[str, int]]], failures: list[str]
) -> None:
    """Print the Markdown summary, also to the GitHub Actions job summary."""
    names = ("total", *(severity.lower() for severity in SEVERITIES))
    lines = [
        "## Container image scans\n",
        "| Image | Scanner | Total | Critical | High | Medium | Low |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        *(
            f"| `{image}` | {scanner} | "
            + " | ".join(str(counts[name]) for name in names)
            + " |"
            for image, scanner, counts in rows
        ),
        *(["", "### Failed", ""] if failures else []),
        *(f"- ❌ {failure}" for failure in failures),
    ]
    text = "\n".join(lines) + "\n"
    print(f"\n{text}")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as summary:
            summary.write(text)


def open_table() -> Any:
    """The DynamoDB table - fails early when credentials or table are wrong.

    The table has only 25 WCU - throttled requests are retried.
    """
    table = boto3.resource(
        "dynamodb",
        region_name=os.environ.get("AWS_REGION", "eu-central-1"),
        config=Config(retries={"mode": "adaptive", "max_attempts": 10}),
    ).Table(os.environ.get("DYNAMODB_TABLE", "container-image-scans"))
    table.load()
    return table


def update_databases() -> dict[str, dict[str, str]]:
    """Update the vulnerability databases once, return the scanner info.

    All scans use these databases (and scanner_info() dates) - exits when an
    update fails.
    """
    print("📥 Updating the trivy and grype vulnerability databases ...")
    for update in (
        ["trivy", "image", "--download-db-only", "--no-progress", "--quiet"],
        ["grype", "db", "update"],
    ):
        result = run(update)
        if result.returncode != 0:
            print(result.stdout + result.stderr, file=sys.stderr)
            sys.exit(f"ERROR: {' '.join(update)} failed")
    os.environ["GRYPE_DB_AUTO_UPDATE"] = "false"
    return scanner_info()


def pull(image: str) -> bool:
    """Pull an image (False when it failed)."""
    result = run(["docker", "pull", image])
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        print(f"  WARNING: failed to pull {image}, skipped")
    return result.returncode == 0


def main() -> int:
    """Scan all images, optionally upload the results; exit 1 on failures."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", choices=["scan", "upload"])
    uploading = parser.parse_args().command == "upload"

    images = load_images(
        Path(os.environ.get("IMAGES_FILE") or REPO_ROOT / "images.yml")
    )
    table = open_table() if uploading else None
    info = update_databases()
    scanned_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"👉 Images to scan: {len(images)}")

    rows: list[tuple[str, str, dict[str, int]]] = []
    failures: list[str] = []
    if table is not None:
        try:
            write_day(table, scanned_at)
        except (BotoCoreError, ClientError) as error:
            print(f"ERROR: day upload failed: {error}", file=sys.stderr)
            failures.append(f"day {scanned_at[:10]} (upload)")
    for number, image in enumerate(images, start=1):
        print(
            f"\n{'=' * 80}\n✴️ Scanning [{number}/{len(images)}]: "
            f"{image.group} / {image.vendor}: {image.image}\n{'=' * 80}"
        )
        if not pull(image.image):
            failures.append(f"{image.image} (pull)")
            continue
        metadata = image_metadata(image.image)
        print(f"💡 Digest: {metadata['digest']}")

        with tempfile.TemporaryDirectory() as workdir:
            for scanner in ("trivy", "grype"):
                cves = scan(image.image, scanner, Path(workdir))
                print(summary_line(scanner, cves))
                if cves is None:
                    # The dashboard keeps the previous result, not "0 CVEs"
                    failures.append(f"{image.image} ({scanner})")
                    continue
                rows.append((image.image, scanner, severity_counts(cves)))
                if table is None:
                    continue
                print(f"  Uploading {len(cves)} CVE records ...")
                try:
                    upload(
                        table,
                        scan_items(
                            image,
                            scanner,
                            {**info[scanner], **metadata},
                            cves,
                            scanned_at,
                        ),
                        cves,
                    )
                except (BotoCoreError, ClientError) as error:
                    # The other scans are still uploaded
                    print(f"  ERROR: upload failed: {error}", file=sys.stderr)
                    failures.append(f"{image.image} ({scanner} upload)")

        # The CI runner can not keep dozens of images (locally they stay)
        if os.environ.get("CI") == "true":
            run(["docker", "rmi", image.image])

    print_summary(rows, failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
