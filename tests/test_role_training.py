"""Feature-family ablations and reproducible registration of training runs."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vulnassess import role_model
from vulnassess.errors import ConfigError
from vulnassess.repository import AssessmentRepository

SYNTHETIC = Path(__file__).resolve().parents[1] / "tests" / "synthetic"


def _examples() -> list[role_model.LabelledHost]:
    return role_model.load_examples(SYNTHETIC / "synthetic_role_train.jsonl")


class FeatureFamilyFiltering(unittest.TestCase):
    def test_unknown_family_is_rejected(self):
        with self.assertRaises(ConfigError):
            role_model.train(_examples(), feature_families=["banners"])

    def test_empty_family_list_is_rejected(self):
        with self.assertRaises(ConfigError):
            role_model.train(_examples(), feature_families=[])

    def test_structure_only_training_drops_banner_and_product_features(self):
        model = role_model.train(_examples(), feature_families=["structure"])
        self.assertTrue(model.features)
        for feature in model.features:
            self.assertTrue(
                feature.startswith(("port=", "port_proto=", "tls=")),
                f"non-structural feature leaked: {feature}",
            )
        self.assertEqual(model.training["feature_families"], ["structure"])

    def test_default_training_uses_all_families(self):
        model = role_model.train(_examples())
        self.assertEqual(model.training["feature_families"], "all")
        restricted = role_model.train(_examples(), feature_families=["structure"])
        self.assertGreater(len(model.features), len(restricted.features))

    def test_banner_only_model_cannot_reuse_structure_features(self):
        full = role_model.train(_examples())
        banner_only = role_model.train(_examples(), feature_families=["banner"])
        self.assertTrue(banner_only.features)
        self.assertNotIn("port=443", banner_only.features)
        self.assertIn("port=443", full.features)


class FeatureAblation(unittest.TestCase):
    def test_cli_forwards_requested_training_options(self) -> None:
        from vulnassess.cli import main

        with (
            patch.object(
                role_model, "ablate_features", return_value={"examples": 54, "results": []}
            ) as ablate,
            redirect_stdout(io.StringIO()),
        ):
            code = main(
                [
                    "model",
                    "ablate",
                    "--data",
                    str(SYNTHETIC / "synthetic_role_train.jsonl"),
                    "--allow-synthetic",
                    "--epochs",
                    "7",
                    "--folds",
                    "2",
                    "--learning-rate",
                    "0.1",
                    "--families",
                    "structure",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(ablate.call_args.kwargs.get("epochs"), 7)
        self.assertEqual(ablate.call_args.kwargs.get("learning_rate"), 0.1)
        self.assertEqual(ablate.call_args.kwargs["subsets"], [["structure"]])

    def test_cli_rejects_conflicting_family_selectors(self) -> None:
        from vulnassess.cli import main

        with patch.object(role_model, "ablate_features") as ablate:
            code = main(
                [
                    "model",
                    "ablate",
                    "--data",
                    str(SYNTHETIC / "synthetic_role_train.jsonl"),
                    "--allow-synthetic",
                    "--families",
                    "structure",
                    "--subsets",
                    "all",
                ]
            )
        self.assertEqual(code, ConfigError.exit_code)
        ablate.assert_not_called()

    def test_default_ablation_covers_every_family_and_no_banner(self):
        result = role_model.ablate_features(_examples(), folds=2)
        subsets = [entry["subset"] for entry in result["results"]]
        self.assertIn("all", subsets)
        for family in role_model.FEATURE_FAMILIES:
            self.assertIn(family, subsets)
        self.assertIn("os+product+service+structure", subsets)  # everything except banner

    def test_every_subset_uses_the_same_dataset_hash(self):
        result = role_model.ablate_features(_examples(), folds=2)
        hashes = {entry["dataset_hash"] for entry in result["results"]}
        self.assertEqual(len(hashes), 1)

    def test_explicit_subsets_are_respected(self):
        result = role_model.ablate_features(
            _examples(), folds=2, subsets=[["structure"], ["structure", "service"]]
        )
        self.assertEqual(
            sorted(entry["subset"] for entry in result["results"]),
            ["service+structure", "structure"],
        )


class TrainingRegistration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_env = os.environ.pop("VULNASS_DATABASE_URL", None)
        self.database = str(Path(self.tmp.name) / "assess.db")
        self.train_data = Path(self.tmp.name) / "train.jsonl"
        self.validation_data = Path(self.tmp.name) / "validation.jsonl"
        self.train_data.write_text(
            (SYNTHETIC / "synthetic_role_train.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.validation_data.write_text(
            (SYNTHETIC / "synthetic_role_validation.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    def tearDown(self):
        if self.old_env is not None:
            os.environ["VULNASS_DATABASE_URL"] = self.old_env
        self.tmp.cleanup()

    def _train(self, *extra: str) -> dict:
        from vulnassess.cli import main

        output = Path(self.tmp.name) / "model.json"
        arguments = [
            "model",
            "train",
            "--data",
            str(self.train_data),
            "--validation",
            str(self.validation_data),
            "--out",
            str(output),
            "--json",
            "--allow-synthetic",
            "--db",
            self.database,
            *extra,
        ]
        code = main(arguments)
        self.assertEqual(code, 0)
        return json.loads(output.read_text(encoding="utf-8"))

    def test_register_writes_dataset_and_run_rows(self):
        payload = self._train("--register", "--dataset-name", "synthetic-roles")
        with AssessmentRepository(self.database, read_only=True) as repo:
            datasets = repo._rows("select * from datasets")
            runs = repo._rows("select * from role_model_runs")
        self.assertEqual(len(datasets), 1)
        self.assertEqual(datasets[0]["name"], "synthetic-roles")
        self.assertEqual(datasets[0]["data_kind"], "synthetic")
        self.assertEqual(runs[0]["model_hash"], payload["model_hash"])
        self.assertEqual(runs[0]["dataset_id"], datasets[0]["id"])
        self.assertIsNotNone(runs[0]["macro_f1"])
        self.assertIn("validation_groups", runs[0]["split"])

    def test_registration_requires_a_dataset_name(self):
        from vulnassess.cli import main

        self.assertNotEqual(
            0,
            main(
                [
                    "model",
                    "train",
                    "--data",
                    str(self.train_data),
                    "--out",
                    str(Path(self.tmp.name) / "m.json"),
                    "--allow-synthetic",
                    "--db",
                    self.database,
                    "--register",
                ]
            ),
        )

    def test_mixed_labels_are_not_registered_as_real_authorised(self) -> None:
        rows = [
            json.loads(line) for line in self.train_data.read_text(encoding="utf-8").splitlines()
        ]
        rows[0].update(label_source="human", reviewer="synthetic-reviewer-for-test")
        self.train_data.write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
        )
        with redirect_stdout(io.StringIO()):
            self._train("--register", "--dataset-name", "synthetic-mixed-label-test")
        with AssessmentRepository(self.database, read_only=True) as repo:
            dataset = repo._rows("select * from datasets")[0]
        self.assertEqual(dataset["data_kind"], "synthetic")

    def test_unregistered_training_leaves_store_empty(self):
        AssessmentRepository(self.database).close()
        self._train()
        with AssessmentRepository(self.database, read_only=True) as repo:
            self.assertEqual(repo._rows("select * from role_model_runs"), [])


if __name__ == "__main__":
    unittest.main()
