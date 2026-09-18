"""Validate and publish only named build artifacts, preserving prior releases."""
import argparse
import hashlib
import shutil
import uuid
import zipfile
from pathlib import Path


def publish(staging, dist, backups):
    if staging == dist or staging in dist.parents or dist in staging.parents:
        raise ValueError("Staging and distribution must be separate directories")
    folder = staging / "OracleReport-FastStart"
    for file in (staging / "OracleReport.exe", folder / "OracleReport.exe",
                 folder / "_internal/resources/ora/catalog.json.gz"):
        if not file.is_file():
            raise RuntimeError("Missing release artifact: " + str(file))
    readme = (Path(__file__).parent / "release_readme.txt").read_text(encoding="utf-8")
    (folder / "使用说明.txt").write_text(readme, encoding="utf-8-sig")
    with zipfile.ZipFile(staging / "OracleReport-FastStart.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(folder.rglob("*")):
            if file.is_file():
                archive.write(file, file.relative_to(staging))
    for name in ("OracleReport.exe", "OracleReport-FastStart.zip"):
        digest = hashlib.sha256((staging / name).read_bytes()).hexdigest().upper()
        (staging / (name + ".sha256")).write_text(digest + "  " + name + "\n", encoding="ascii")

    names = ("OracleReport.exe", "OracleReport.exe.sha256", "OracleReport-FastStart",
             "OracleReport-FastStart.zip", "OracleReport-FastStart.zip.sha256")
    dist.mkdir(parents=True, exist_ok=True)
    backup = backups / uuid.uuid4().hex
    backup.mkdir(parents=True)
    published = []
    moved = []
    try:
        for name in names:
            target = dist / name
            if target.exists():
                # Names are fixed above; never move a workspace or output/report directory.
                shutil.move(str(target), str(backup / name))
                moved.append(name)
            shutil.move(str(staging / name), str(target))
            published.append(name)
    except Exception:
        for name in reversed(published):
            shutil.move(str(dist / name), str(staging / name))
        for name in moved:
            shutil.move(str(backup / name), str(dist / name))
        raise
    print("Release published:", dist)
    print("Previous artifacts preserved:", backup)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--backups", type=Path, required=True)
    args = parser.parse_args()
    publish(args.staging.resolve(), args.dist.resolve(), args.backups.resolve())
