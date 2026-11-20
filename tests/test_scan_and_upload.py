"""Tests of scripts/scan_and_upload.py - no Docker, scanners or AWS needed."""

# Only for subprocess.CompletedProcess (fake command results)
import subprocess  # nosec B404
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

import scan_and_upload as sau

TRIVY_REPORT = {
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                    "Severity": "HIGH",
                    "Title": "zlib: overflow",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2",
                },
                {
                    "VulnerabilityID": "CVE-1",
                    "PkgName": "tar",
                    "InstalledVersion": "2.0",
                    "Severity": "UNKNOWN",
                    "Description": "no title",
                },
            ]
        },
        # Same CVE + package again (e.g. found in another path)
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.0",
                    "Severity": "HIGH",
                }
            ]
        },
        {"Target": "no vulnerabilities"},
    ]
}

GRYPE_REPORT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-3",
                "severity": "Negligible",
                "dataSource": "https://security-tracker.debian.org/CVE-3",
                "fix": {"versions": ["1.2", "1.3"]},
            },
            "relatedVulnerabilities": [{"description": "from NVD"}],
            "artifact": {"name": "perl", "version": "5.40"},
        },
        {
            "vulnerability": {
                "id": "CVE-3",
                "severity": "Critical",
                "description": "own description",
                "fix": {"versions": []},
            },
            "artifact": {"name": "openssl", "version": "3.5"},
        },
    ]
}


def test_load_images(tmp_path: Path) -> None:
    """Groups, vendors and descriptions are read in file order."""
    images_file = tmp_path / "images.yml"
    images_file.write_text(
        "python:\n"
        "  description: Python interpreter\n"
        "  images:\n"
        "    docker:\n"
        "      image: docker.io/python:alpine\n"
        "      description: Docker Official Image\n"
        "base:\n"
        "  images:\n"
        "    alpine:\n"
        "      image: docker.io/alpine:latest\n",
        encoding="utf-8",
    )

    assert sau.load_images(images_file) == [
        sau.Image(
            "python",
            "Python interpreter",
            "docker",
            "docker.io/python:alpine",
            "Docker Official Image",
        ),
        sau.Image("base", "", "alpine", "docker.io/alpine:latest", ""),
    ]


def test_real_images_file() -> None:
    """The repository images.yml is valid and every image is unique."""
    images = sau.load_images(sau.REPO_ROOT / "images.yml")
    assert images
    assert all(image.image and image.description for image in images)
    assert len({image.image for image in images}) == len(images)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CRITICAL", "CRITICAL"),
        ("High", "HIGH"),
        ("medium", "MEDIUM"),
        ("Negligible", "LOW"),
        ("Unknown", "UNKNOWN"),
        ("whatever", "UNKNOWN"),
        (None, "UNKNOWN"),
    ],
)
def test_normalize_severity(value: str | None, expected: str) -> None:
    """Scanner severities map to the dashboard severities."""
    assert sau.normalize_severity(value) == expected


def test_trivy_cves() -> None:
    """One entry per CVE + package, sorted, missing fields are empty."""
    assert sau.trivy_cves(TRIVY_REPORT) == [
        {
            "cve_id": "CVE-1",
            "severity": "UNKNOWN",
            "description": "no title",
            "url": "",
            "package_name": "tar",
            "installed_version": "2.0",
            "fixed_version": "",
        },
        {
            "cve_id": "CVE-2",
            "severity": "HIGH",
            "description": "zlib: overflow",
            "url": "https://avd.aquasec.com/nvd/cve-2",
            "package_name": "zlib",
            "installed_version": "1.0",
            "fixed_version": "1.1",
        },
    ]


def test_grype_cves() -> None:
    """Negligible is LOW, fix versions are joined, NVD text is a fallback."""
    assert sau.grype_cves(GRYPE_REPORT) == [
        {
            "cve_id": "CVE-3",
            "severity": "CRITICAL",
            "description": "own description",
            "url": "",
            "package_name": "openssl",
            "installed_version": "3.5",
            "fixed_version": "",
        },
        {
            "cve_id": "CVE-3",
            "severity": "LOW",
            "description": "from NVD",
            "url": "https://security-tracker.debian.org/CVE-3",
            "package_name": "perl",
            "installed_version": "5.40",
            "fixed_version": "1.2, 1.3",
        },
    ]


@pytest.mark.parametrize("content", ["", "not json", "[1, 2]"])
def test_read_report_invalid(tmp_path: Path, content: str) -> None:
    """Empty, invalid or unexpected reports give no CVEs."""
    report = tmp_path / "report.json"
    report.write_text(content, encoding="utf-8")
    assert not sau.read_report(report)
    assert not sau.read_report(tmp_path / "missing.json")
    assert not sau.trivy_cves(sau.read_report(report))


def test_scan_items() -> None:
    """CVEs go to their own partition, the LATEST item is written last."""
    image = sau.Image("python", "Python", "docker", "python:alpine", "Doc")
    cves = sau.trivy_cves(TRIVY_REPORT)
    info = {"version": "0.76.2", "db": "2026-11-20", "digest": "sha256:0"}

    items = sau.scan_items(image, "trivy", info, cves, "2026-11-20T00:00:00Z")

    expires_at = (
        int(datetime.fromisoformat("2026-11-20T00:00:00Z").timestamp())
        + 2 * 365 * 24 * 60 * 60
    )
    cves_pk = "CVES#python#docker#trivy#2026-11-20T00:00:00Z"
    assert [(item["pk"], item["sk"]) for item in items] == [
        (cves_pk, "CVE-1#tar"),
        (cves_pk, "CVE-2#zlib"),
        ("LATEST", "python#docker#trivy"),
    ]
    assert all(item["expires_at"] == expires_at for item in items)
    assert items[-1] == {
        "pk": "LATEST",
        "sk": "python#docker#trivy",
        "group": "python",
        "group_description": "Python",
        "vendor": "docker",
        "image": "python:alpine",
        "image_description": "Doc",
        "scanner": "trivy",
        "scanner_version": "0.76.2",
        "scanner_db": "2026-11-20",
        "image_digest": "sha256:0",
        "scanned_at": "2026-11-20T00:00:00Z",
        "cves_pk": cves_pk,
        "cve_total": 2,
        "cve_critical": 0,
        "cve_high": 1,
        "cve_medium": 0,
        "cve_low": 0,
        "expires_at": expires_at,
    }


class FakeTable:
    """DynamoDB table stand-in: records how and in which order items land.

    events: ("batch", sk) for batch writer items, ("flushed", "") when the
    batch writer finished, ("put", sk) for a single PutItem.
    """

    def __init__(self, fail_sk: str = "") -> None:
        self.items: list[dict[str, Any]] = []
        self.events: list[tuple[str, str]] = []
        self.loaded = False
        self.fail_sk = fail_sk

    def load(self) -> None:
        """Like Table.load() (DescribeTable)."""
        self.loaded = True

    @contextmanager
    def batch_writer(self):  # type: ignore[no-untyped-def]
        """Like Table.batch_writer(): items are stored when it finishes."""
        batch = FakeBatch()
        yield batch
        for item in batch.items:
            self.items.append(item)
            self.events.append(("batch", item["sk"]))
        self.events.append(("flushed", ""))

    # "Item" like the boto3 keyword argument
    # pylint: disable-next=invalid-name
    def put_item(self, Item: dict[str, Any]) -> None:
        """Like Table.put_item(), fails for the fail_sk item."""
        if Item["sk"] == self.fail_sk:
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException"}},
                "PutItem",
            )
        self.items.append(Item)
        self.events.append(("put", Item["sk"]))


class FakeBatch:  # pylint: disable=too-few-public-methods
    """Batch writer stand-in collecting the items."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    # pylint: disable-next=invalid-name
    def put_item(self, Item: dict[str, Any]) -> None:
        """Like the batch writer put_item()."""
        self.items.append(Item)


def test_write_items_writes_latest_after_all_cves() -> None:
    """LATEST is a separate PutItem after the batch writer finished."""
    image = sau.Image("python", "Python", "docker", "python:alpine", "Doc")
    info = {"version": "1", "db": "2", "digest": "sha256:0"}
    items = sau.scan_items(
        image,
        "trivy",
        info,
        sau.trivy_cves(TRIVY_REPORT),
        "2026-11-20T00:00:00Z",
    )
    table = FakeTable()

    sau.write_items(table, items)

    assert table.events == [
        ("batch", "CVE-1#tar"),
        ("batch", "CVE-2#zlib"),
        ("flushed", ""),
        ("put", "python#docker#trivy"),
    ]


def test_scan_skips_secret_scanning_and_db_updates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Scans only look for vulnerabilities with the databases of the run."""
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(sau, "run", fake_run)

    sau.scan("alpine:latest", "trivy", tmp_path)
    sau.scan("alpine:latest", "grype", tmp_path)
    assert {"--scanners", "vuln", "--skip-db-update"} <= set(commands[0])
    assert commands[1][:3] == ["grype", "alpine:latest", "--by-cve"]


@pytest.mark.parametrize(
    ("scanner", "report", "expected"),
    [
        # Valid reports without vulnerabilities: 0 CVEs
        ("trivy", '{"SchemaVersion": 2, "Results": []}', []),
        ("grype", '{"matches": []}', []),
        # Missing, invalid or foreign reports: a failed scan, not 0 CVEs
        ("trivy", None, None),
        ("trivy", "not json", None),
        ("trivy", '{"matches": []}', None),
        ("grype", '{"SchemaVersion": 2}', None),
    ],
)
def test_scan_rejects_invalid_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scanner: str,
    report: str | None,
    expected: list[sau.CVE] | None,
) -> None:
    """A scan that exits 0 without a valid report is a failed scan."""

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        if report is not None:
            (tmp_path / f"{scanner}.json").write_text(report, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(sau, "run", fake_run)

    assert sau.scan("alpine:latest", scanner, tmp_path) == expected


def fake_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    table: FakeTable,
    failing: tuple[str, ...] = (),
) -> None:
    """Prepare main(): images good / broken / half, fake commands + table.

    failing: commands (joined by spaces) that exit with 1.
    """
    images_file = tmp_path / "images.yml"
    images_file.write_text(
        "base:\n"
        "  images:\n"
        "    good: {image: good:latest, description: Good}\n"
        "    broken: {image: broken:latest, description: Not pullable}\n"
        "    half: {image: half:latest, description: grype fails}\n",
        encoding="utf-8",
    )

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        failed = " ".join(command) in failing
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "")

    def fake_scan(image: str, scanner: str, _: Path) -> list[sau.CVE] | None:
        if image == "half:latest" and scanner == "grype":
            return None
        return sau.trivy_cves(TRIVY_REPORT)

    monkeypatch.setenv("IMAGES_FILE", str(images_file))
    monkeypatch.setattr("sys.argv", ["scan_and_upload.py", "upload"])
    monkeypatch.setattr(sau, "run", fake_run)
    monkeypatch.setattr(sau, "scan", fake_scan)
    monkeypatch.setattr(sau, "image_digest", lambda _: "sha256:0")
    monkeypatch.setattr(
        sau,
        "scanner_info",
        lambda: {s: {"version": "1", "db": "2"} for s in ("trivy", "grype")},
    )
    monkeypatch.setattr(
        sau.boto3,
        "resource",
        lambda *_, **__: type("R", (), {"Table": lambda _, __: table})(),
    )


def test_main_uploads_good_scans_and_reports_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    """Failed pulls, scans and uploads are skipped and reported, exit 1."""
    table = FakeTable(fail_sk="base#good#grype")
    fake_main(
        monkeypatch, tmp_path, table, failing=("docker pull broken:latest",)
    )

    assert sau.main() == 1

    assert table.loaded
    latest = [item["sk"] for item in table.items if item["pk"] == "LATEST"]
    assert latest == ["base#good#trivy", "base#half#trivy"]
    output = capsys.readouterr().out
    assert "❌ Failed: broken:latest (pull)" in output
    assert "❌ Failed: good:latest (grype upload)" in output
    assert "❌ Failed: half:latest (grype)" in output


def test_main_stops_when_a_database_update_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without a fresh vulnerability database nothing is scanned."""
    table = FakeTable()
    fake_main(monkeypatch, tmp_path, table, failing=("grype db update",))

    with pytest.raises(SystemExit, match="grype db update failed"):
        sau.main()

    assert not table.items
