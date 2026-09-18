"""Explicit --verify-package diagnostics; never run during normal startup."""
import json
import tempfile
import traceback
from pathlib import Path


def verify_package(output):
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = {"ok": False}
    root = None
    try:
        from tkinterdnd2 import TkinterDnD, DND_FILES
        import tkinter as tk
        root = TkinterDnD.Tk()
        root.withdraw()
        target = tk.Frame(root)
        target.drop_target_register(DND_FILES)
        target.dnd_bind("<<Drop>>", lambda event: "copy")
        root.update_idletasks()
        result["tkdnd"] = root.TkdndVersion
        from ora_knowledge import catalog_metadata, lookup_code, _catalog_path
        result["catalog"] = catalog_metadata()
        result["compressed_catalog"] = str(_catalog_path()).endswith(".gz")
        assert lookup_code("ORA-00600")["known"]

        from report_gen import build_reports
        import docx_gen
        # Exercise standalone DOCX generation without launching a local Office app.
        original_pagination = docx_gen._cache_toc_page_numbers
        docx_gen._cache_toc_page_numbers = lambda path: False
        try:
            with tempfile.TemporaryDirectory(prefix="orasentry-package-", dir=destination.parent) as directory:
                base = Path(directory)
                inputs = []
                for name, kind, platform in (("host", "host", "linux"),
                                              ("orcl", "db", "linux"),
                                              ("prod", "db", "windows")):
                    raw = base / name
                    (raw / kind).mkdir(parents=True)
                    if kind == "db":
                        (raw / "security").mkdir()
                    (raw / "env.info").write_text(
                        "hostname=package-test\ntimestamp=20260907_120000\n"
                        + "platform=" + platform + "\ncheck_type=" + kind + "\n"
                        + ("oracle_sid=" + name + "\n" if kind == "db" else ""), encoding="utf-8")
                    (raw / "collection_manifest.tsv").write_text(
                        "item\ttype\tstatus\texit_code\tmessage\n", encoding="utf-8")
                    inputs.append(str(raw))
                report_dir = base / "reports"
                report_dir.mkdir()
                batch = build_reports(inputs, str(report_dir), generate_summary_content=True)
                assert not batch.errors, batch.errors
                assert len(batch.reports) == 3, len(batch.reports)
                assert batch.summary_html and batch.summary_docx
                from docx import Document
                outputs = [path for report in batch.reports for path in (report.html, report.docx)]
                outputs += [batch.summary_html, batch.summary_docx]
                for path in outputs:
                    assert Path(path).stat().st_size > 0
                    if path.endswith(".docx"):
                        assert Document(path).paragraphs
                result["generated_files"] = len(outputs)
                result["reports"] = len(batch.reports)
        finally:
            docx_gen._cache_toc_page_numbers = original_pagination
        result["ok"] = True
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        if root is not None:
            root.destroy()
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if result["ok"] else 1
