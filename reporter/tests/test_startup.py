import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from publish_release import publish


class StartupTests(unittest.TestCase):
    def test_gui_import_leaves_report_dependencies_unloaded(self):
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        script = """
import sys
import gui
for name in ('report_gen', 'docx', 'lxml', 'ora_knowledge',
             'parser.host_parser', 'parser.db_parser', 'parser.security_parser'):
    assert name not in sys.modules, name
from parser import parse_host, parse_db, parse_security
assert callable(parse_host) and callable(parse_db) and callable(parse_security)
"""
        completed = subprocess.run([sys.executable, "-c", script], env=environment,
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)


class ReleasePublicationTests(unittest.TestCase):
    def make_staging(self, base):
        staging = base / "staging"
        internal = staging / "OracleReport-FastStart/_internal/resources/ora"
        internal.mkdir(parents=True)
        (internal / "catalog.json.gz").write_bytes(b"fixture")
        (staging / "OracleReport.exe").write_bytes(b"new-portable")
        (staging / "OracleReport-FastStart/OracleReport.exe").write_bytes(b"new-folder")
        return staging

    def test_previous_release_and_unrelated_data_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = self.make_staging(base)
            dist = base / "dist"
            dist.mkdir()
            (dist / "OracleReport.exe").write_bytes(b"old-portable")
            (dist / "user-report.html").write_bytes(b"user-data")
            publish(staging, dist, base / "backups")
            self.assertEqual((dist / "user-report.html").read_bytes(), b"user-data")
            self.assertEqual((dist / "OracleReport.exe").read_bytes(), b"new-portable")
            backups = list((base / "backups").glob("*/OracleReport.exe"))
            self.assertEqual(backups[0].read_bytes(), b"old-portable")
            self.assertTrue((dist / "OracleReport-FastStart.zip.sha256").is_file())

    def test_failed_replacement_restores_previous_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            staging = self.make_staging(base)
            dist = base / "dist"
            dist.mkdir()
            (dist / "OracleReport.exe").write_bytes(b"old-portable")
            import shutil
            move = shutil.move
            def fail_new_executable(source, target):
                if Path(source) == staging / "OracleReport.exe":
                    raise PermissionError("simulated file lock")
                return move(source, target)
            with patch("publish_release.shutil.move", side_effect=fail_new_executable):
                with self.assertRaises(PermissionError):
                    publish(staging, dist, base / "backups")
            self.assertEqual((dist / "OracleReport.exe").read_bytes(), b"old-portable")
