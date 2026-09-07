import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ora_knowledge import CatalogError, catalog_metadata, load_catalog, lookup_code, _validate_catalog


class OraKnowledgeTests(unittest.TestCase):
    def test_catalog_metadata_is_lightweight_and_complete(self):
        metadata = catalog_metadata()
        self.assertEqual(metadata["catalog_version"], "2026.09.07-v3")
        self.assertEqual(metadata["entry_count"], 5386)
        self.assertNotIn("entries", metadata)

    def test_catalog_is_self_describing_and_returns_owned_records(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog["entries"]), 5386)
        self.assertGreaterEqual(sum(e["code"].startswith("ORA-") for e in catalog["entries"]), 5000)
        self.assertIn("第三版", catalog["coverage_note"])
        record = lookup_code("ora-600", "19.18.0.0.0")
        self.assertEqual(record["code"], "ORA-00600")
        self.assertEqual(record["severity"], "CRIT")
        self.assertIn("19.18", record["version_note"])
        self.assertIn("未逐版本核验", record["version_note"])
        self.assertIn("internal error code", record["official_title"])
        record["checks"].clear()
        catalog["entries"].clear()
        self.assertTrue(lookup_code("ORA-00600")["checks"])
        self.assertEqual(len(load_catalog()["entries"]), 5386)

    def test_domain_entries_keep_official_message_and_safe_diagnosis(self):
        record = lookup_code("ORA-00017", "21c")
        self.assertTrue(record["known"])
        self.assertEqual(record["diagnostic_level"], "domain")
        self.assertTrue(record["official_title"])
        self.assertTrue(record["checks"])
        self.assertTrue(record["actions"])
        self.assertIn("21c", record["versions"])

    def test_unknown_and_customer_codes_are_explicit(self):
        for code in ("ORA-999999", "ORA-20001", "RMAN-99999"):
            entry = lookup_code(code)
            self.assertFalse(entry["known"])
            self.assertEqual(entry["severity"], "UNKNOWN")
            self.assertTrue(entry["checks"])
            self.assertTrue(entry["actions"])
            self.assertEqual(entry["causes"], [])
        self.assertEqual(lookup_code("ORA-20001")["category"], "应用自定义")

    def test_standalone_and_frozen_resource_lookup(self):
        catalog = load_catalog()
        with tempfile.TemporaryDirectory() as directory:
            resource = Path(directory) / "resources" / "ora" / "catalog.json"
            resource.parent.mkdir(parents=True)
            resource.write_text(json.dumps(catalog, ensure_ascii=False), encoding="utf-8")
            with patch.object(sys, "frozen", True, create=True), patch.object(sys, "_MEIPASS", directory, create=True):
                self.assertTrue(lookup_code("ORA-00313")["known"])
                resource.unlink()
                with self.assertRaises(CatalogError):
                    load_catalog()

    def test_invalid_catalog_cannot_silently_change_diagnosis(self):
        catalog = load_catalog()
        invalids = []
        duplicate = copy.deepcopy(catalog)
        duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
        invalids.append(duplicate)
        wrong_level = copy.deepcopy(catalog)
        wrong_level["entries"][0]["severity"] = "FINE"
        invalids.append(wrong_level)
        unsafe_link = copy.deepcopy(catalog)
        unsafe_link["entries"][0]["source_url"] = "javascript:alert(1)"
        invalids.append(unsafe_link)
        unsupported = copy.deepcopy(catalog)
        unsupported["schema_version"] = 999
        invalids.append(unsupported)
        for value in invalids:
            with self.assertRaises(CatalogError):
                _validate_catalog(value)


if __name__ == "__main__":
    unittest.main()
