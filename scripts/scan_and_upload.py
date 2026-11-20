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


def severity_counts(cves: list[CVE]) -> dict[str, int]:
    """Count the CVEs: total + per severity."""
    counts = {"total": len(cves)}
    for severity in SEVERITIES:
        counts[severity.lower()] = sum(
            1 for cve in cves if cve["severity"] == severity
        )
    return counts


def scan_items(
    image: Image,
    scanner: str,
    info: dict[str, str],
    cves: list[CVE],
    scanned_at: str,
) -> list[dict[str, Any]]:
    """Build the DynamoDB items of one scan: CVEs first, LATEST last.

    The CVEs get their own partition, the LATEST item points to it (see
    write_items()). LATEST is keyed by group + vendor (not the image name),
    so a new image of the same vendor replaces the old dashboard row.
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
    items.append(
        {
            "pk": "LATEST",
            "sk": key,
            "group": image.group,
            "group_description": image.group_description,
            "vendor": image.vendor,
            "image": image.image,
            "image_description": image.description,
            "scanner": scanner,
            "scanner_version": info["version"],
            "scanner_db": info["db"],
            "image_digest": info["digest"],
            "scanned_at": scanned_at,
            "cves_pk": cves_pk,
            **{f"cve_{name}": count for name, count in counts.items()},
            "expires_at": expires_at,
        }
    )
    return items


def write_items(table: Any, items: list[dict[str, Any]]) -> None:
    """Write the CVEs of one scan, then its LATEST item (the last one).

    batch_writer() sends 25 items per request and resends throttled
    (unprocessed) items - at the end of its queue, so out of order. LATEST
    is written only after all CVEs are stored: the dashboard never sees a
    half-written scan. The client retries throttling errors (adaptive
    retry mode, see main()).
    """
    *cves, latest = items
    with table.batch_writer() as batch:
        for item in cves:
            batch.put_item(Item=item)
    table.put_item(Item=latest)


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


def image_digest(image: str) -> str:
    """Digest of a pulled image (sha256:...) or "unknown"."""
    result = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}",
            image,
        ]
    )
    digest = result.stdout.strip().rpartition("@")[2]
    return digest if result.returncode == 0 and digest else "unknown"


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
    return (
        trivy_cves(report_data)
        if scanner == "trivy"
        else grype_cves(report_data)
    )


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


def print_summary(rows: list[tuple[str, str, dict[str, int]]]) -> None:
    """Print the final table of all scans."""
    names = ("total", *(severity.lower() for severity in SEVERITIES))
    table = [
        ("IMAGE", "SCANNER", "TOTAL", "CRIT", "HIGH", "MED", "LOW"),
        *(
            (image, scanner, *(str(counts[name]) for name in names))
            for image, scanner, counts in rows
        ),
    ]
    width = max(len(line[0]) for line in table)
    table.insert(1, ("-" * width, "-" * 7, "-" * 5, *["----"] * 4))
    print(f"\n{'=' * 80}\nSummary\n{'=' * 80}\n")
    for image, scanner, total, *severities in table:
        print(
            f"{image:<{width}}  {scanner:<7}  {total:>5}  "
            + "  ".join(f"{value:>4}" for value in severities)
        )


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
    upload = parser.parse_args().command == "upload"

    images = load_images(
        Path(os.environ.get("IMAGES_FILE") or REPO_ROOT / "images.yml")
    )
    table = open_table() if upload else None
    info = update_databases()
    scanned_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"👉 Images to scan: {len(images)}")

    rows: list[tuple[str, str, dict[str, int]]] = []
    failures: list[str] = []
    for number, image in enumerate(images, start=1):
        print(
            f"\n{'=' * 80}\n✴️ Scanning [{number}/{len(images)}]: "
            f"{image.group} / {image.vendor}: {image.image}\n{'=' * 80}"
        )
        if not pull(image.image):
            failures.append(f"{image.image} (pull)")
            continue
        digest = image_digest(image.image)
        print(f"💡 Digest: {digest}")

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
                    write_items(
                        table,
                        scan_items(
                            image,
                            scanner,
                            {**info[scanner], "digest": digest},
                            cves,
                            scanned_at,
                        ),
                    )
                except (BotoCoreError, ClientError) as error:
                    # The other scans are still uploaded
                    print(f"  ERROR: upload failed: {error}", file=sys.stderr)
                    failures.append(f"{image.image} ({scanner} upload)")

        # The CI runner can not keep dozens of images (locally they stay)
        if os.environ.get("CI") == "true":
            run(["docker", "rmi", image.image])

    print_summary(rows)
    if failures:
        print("\n" + "\n".join(f"❌ Failed: {f}" for f in failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
