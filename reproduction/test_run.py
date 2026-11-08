import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
import run
from dependencies import checkout


class ReproductionValidationTests(unittest.TestCase):
    def test_rejects_existing_dependency_with_wrong_revision_or_dirty_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            dependency = Path(temporary)
            for revision, status in [("wrong", ""), ("pinned", "?? src/extra.rs")]:
                with self.subTest(revision=revision, status=status):
                    with patch("dependencies.subprocess.check_output",
                               side_effect=[revision, status]), patch("dependencies.subprocess.run") as execute:
                        with self.assertRaisesRegex(ValueError, "dependency must be clean"):
                            checkout(dependency, "unused", "pinned")
                        execute.assert_not_called()

    def test_rejects_modified_corpus(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, "APPS", ("github",)), patch.object(run, "SIZES", (5,)):
            root = Path(temporary)
            corpus = root / "corpus"
            point = corpus / "github/5"
            point.mkdir(parents=True)
            (point / "metadata.json").write_text("{}")
            (point / "1.json").write_text('{"original":true}')
            run.save_json(corpus / "manifest.json", {
                "format_version": 1, "preset": "smoke", "upstream_commit": run.UPSTREAM,
                "versions": run.VERSIONS,
                "apps": ["github"], "sizes": [5], "num_hierarchies": 1,
                "files": run.corpus_files(corpus),
            })
            with patch.object(run, "ROOT", root):
                run.verify_corpus(corpus, "smoke")
                (point / "1.json").write_text('{"original":false}')
                with self.assertRaisesRegex(ValueError, "checksums"):
                    run.verify_corpus(corpus, "smoke")

    def test_rejects_corpus_from_other_generator_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary)
            run.save_json(corpus / "manifest.json", {
                "format_version": 1, "preset": "smoke", "upstream_commit": run.UPSTREAM,
                "apps": list(run.APPS), "versions": {**run.VERSIONS, "spec_commit": "different"},
            })
            with self.assertRaisesRegex(ValueError, "dependency revisions"):
                run.verify_corpus(corpus, "smoke")

    def test_validates_and_preserves_raw_samples(self):
        self.check_samples(mismatch=False)

    def test_rejects_decision_mismatch(self):
        self.check_samples(mismatch=True)

    def test_rejects_incorrect_precise_median(self):
        self.check_samples(mismatch=False, incorrect_median=True)

    def check_samples(self, mismatch, incorrect_median=False):
        with tempfile.TemporaryDirectory() as temporary, patch.object(run, "SIZES", (5,)):
            directory = Path(temporary)
            pd.DataFrame([{
                "num_entities": 5, "cedar median_dur_micros": 1.25 if incorrect_median else 1,
                "rego median_dur_micros": 2,
            }]).to_csv(directory / "github.csv", index=False)
            rows = []
            for request in range(2):
                for engine, nanos in [("cedar", 1000), ("rego", 2000)]:
                    rows.append({
                        "app": "github", "num_entities": 5, "hierarchy": 1,
                        "engine": engine, "request": request, "duration_ns": nanos,
                        "decision": "Deny" if mismatch and engine == "rego" else "Allow",
                        "errors": 0,
                    })
            path = directory / "github-5-8192-samples.csv"
            pd.DataFrame(rows).to_csv(path, index=False)
            if mismatch:
                with self.assertRaisesRegex(ValueError, "decision mismatch"):
                    run.analyze_run(directory, ["github"], ["original"], 1, 2, 1)
                self.assertTrue(path.exists())
            elif incorrect_median:
                with self.assertRaisesRegex(ValueError, "aggregate median"):
                    run.analyze_run(directory, ["github"], ["original"], 1, 2, 1)
                self.assertTrue(path.exists())
            else:
                summary, checked = run.analyze_run(directory, ["github"], ["original"], 1, 2, 1)
                self.assertEqual(checked, 2)
                self.assertEqual(summary[0]["opa_over_cedar"], 2)
                self.assertTrue(Path(str(path) + ".gz").exists())


if __name__ == "__main__":
    unittest.main()
