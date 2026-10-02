import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from sentinel_content import arm, build, cli, rules, workbooks

RULES, BOOKS, SCHEMA = build.load_all()


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class GeneratedFileTests(unittest.TestCase):
    def test_the_sources_have_no_problems(self):
        self.assertEqual(build.problems(RULES, BOOKS, SCHEMA), [])

    def test_the_committed_files_match_the_sources(self):
        # If this fails, run: python -m sentinel_content build
        self.assertEqual(build.stale_files(build.generated_files(RULES, BOOKS), rules.CONTENT_ROOT), [])

    def test_the_expected_files_are_generated(self):
        names = {path.as_posix() for path in build.generated_files(RULES, BOOKS)}
        self.assertIn("Detection-rules/deploy/all-rules.json", names)
        self.assertIn("Detection-rules/CATALOGUE.md", names)
        self.assertIn("Workbooks/deploy/all-workbooks.json", names)
        for area in rules.AREAS:
            self.assertIn(f"Detection-rules/deploy/{area}.json", names)
        for book in BOOKS:
            self.assertIn(f"Workbooks/{book.file}.json", names)
        self.assertEqual(len(names), 1 + 7 + 1 + 7 + 1)

    def test_write_then_compare_in_a_scratch_folder(self):
        files = build.generated_files(RULES, BOOKS)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertEqual(len(build.stale_files(files, root)), len(files))
            self.assertEqual(len(build.write_files(files, root)), len(files))
            self.assertEqual(build.write_files(files, root), [])
            self.assertEqual(build.stale_files(files, root), [])
            target = root / "Workbooks" / f"{BOOKS[0].file}.json"
            target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
            (root / "Detection-rules" / "deploy" / "old-area.json").write_text("{}", encoding="utf-8")
            stale = build.stale_files(files, root)
            self.assertEqual(len(stale), 2)
            self.assertTrue(any("out of date" in line for line in stale))
            self.assertTrue(any("old-area.json has no rules behind it" in line for line in stale))

    def test_generated_text_uses_unix_line_endings_and_ends_with_a_newline(self):
        for path, text in build.generated_files(RULES, BOOKS).items():
            self.assertTrue(text.endswith("\n"), path)
            if path.suffix == ".md":
                self.assertNotIn("\r", text, path)


class RuleTemplateTests(unittest.TestCase):
    def test_template_shape(self):
        template = arm.rules_template(RULES)
        self.assertEqual(template["$schema"], arm.TEMPLATE_SCHEMA)
        self.assertEqual(list(template["parameters"]), ["workspace"])
        self.assertEqual(len(template["resources"]), 28)
        for rule, resource in zip(RULES, template["resources"]):
            self.assertEqual(resource["type"], "Microsoft.OperationalInsights/workspaces/providers/alertRules")
            self.assertEqual(resource["kind"], "Scheduled")
            self.assertEqual(resource["apiVersion"], "2024-03-01")
            self.assertEqual(resource["name"], f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/{rule.guid}')]")
            self.assertIn(rule.guid, resource["id"])
            self.assertEqual(resource["properties"]["displayName"], rule.title)
            self.assertIs(resource["properties"]["enabled"], False)

    def test_enabled_templates_are_only_built_on_request(self):
        template = arm.rules_template(RULES[:2], enabled=True)
        self.assertTrue(all(resource["properties"]["enabled"] is True for resource in template["resources"]))

    def test_area_templates_add_up_to_the_full_template(self):
        files = build.generated_files(RULES, BOOKS)
        everything = json.loads(files[Path("Detection-rules/deploy/all-rules.json")])["resources"]
        by_area = []
        for area in rules.AREAS:
            by_area.extend(json.loads(files[Path(f"Detection-rules/deploy/{area}.json")])["resources"])
        self.assertEqual(by_area, everything)

    def test_no_text_is_mistaken_for_an_arm_expression(self):
        self.assertEqual(arm.literal("[looks like an expression]"), "[[looks like an expression]")
        self.assertEqual(arm.literal("[only the start"), "[only the start")
        self.assertEqual(arm.literal({"a": ["[x]", 1, True, None]}), {"a": ["[[x]", 1, True, None]})

        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)
            elif isinstance(value, dict):
                for item in value.values():
                    yield from strings(item)

        for resource in arm.rules_template(RULES)["resources"]:
            for text in strings(resource["properties"]):
                self.assertFalse(text.startswith("[") and text.endswith("]") and not text.startswith("[["), text[:80])


class WorkbookTemplateTests(unittest.TestCase):
    def test_template_shape(self):
        template = arm.workbooks_template(BOOKS, RULES)
        self.assertEqual(set(template["parameters"]), {"workspace", "location"})
        self.assertEqual(len(template["resources"]), 7)
        names = set()
        for book, resource in zip(BOOKS, template["resources"]):
            self.assertEqual(resource["type"], "Microsoft.Insights/workbooks")
            self.assertEqual(resource["kind"], "shared")
            properties = resource["properties"]
            self.assertEqual(properties["displayName"], book.name)
            self.assertEqual(properties["category"], "sentinel")
            self.assertEqual(properties["sourceId"], "[variables('workspaceId')]")
            self.assertEqual(json.loads(properties["serializedData"]), workbooks.gallery(book, RULES))
            self.assertTrue(properties["serializedData"].startswith("{"))
            self.assertTrue(resource["name"].startswith("[guid(variables('workspaceId'), "))
            names.add(resource["name"])
        self.assertEqual(len(names), 7)


class CatalogueAndExportTests(unittest.TestCase):
    def test_the_catalogue_describes_every_rule(self):
        text = build.catalogue(RULES, BOOKS)
        for rule in RULES:
            self.assertIn(f"### {rule.id}", text)
            self.assertIn(rule.title, text)
            self.assertIn(f"({rule.area}/{rule.path.name})", text)
        for book in BOOKS:
            self.assertIn(f"../Workbooks/{book.file}.json", text)
        self.assertEqual(text.count("**What it finds.**"), 28)

    def test_links_in_the_catalogue_point_at_files_that_exist(self):
        import re

        text = build.catalogue(RULES, BOOKS)
        folder = rules.RULES_DIR
        generated = {path.name for path in build.generated_files(RULES, BOOKS)}
        for target in re.findall(r"\]\(([^)#]+)\)", text):
            path = (folder / target).resolve()
            self.assertTrue(path.exists() or path.name in generated, target)

    def test_readable_durations(self):
        self.assertEqual(build.readable_duration("PT1H"), "1 hour")
        self.assertEqual(build.readable_duration("PT30M"), "30 minutes")
        self.assertEqual(build.readable_duration("P14D"), "14 days")
        self.assertEqual(build.readable_duration("P1DT12H"), "36 hours")

    def test_the_query_export_covers_every_query(self):
        queries = json.loads(build.query_export(RULES, BOOKS))
        workbook_total = sum(len(workbooks.workbook_queries(book, RULES)) for book in BOOKS)
        self.assertEqual(len(queries), len(RULES) + workbook_total)
        self.assertEqual(len({query["id"] for query in queries}), len(queries))
        for query in queries:
            self.assertEqual(set(query), {"id", "source", "query", "columns", "exact"})
            self.assertNotIn("{TimeRange", query["query"])
            self.assertFalse(query["query"].lstrip().startswith("//"))
        first = queries[0]
        self.assertEqual(first["id"], "ID-001")
        self.assertIn("IPAddress", first["columns"])


class CommandLineTests(unittest.TestCase):
    def test_check_and_list(self):
        code, out, err = run("check")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("28 rules, 7 workbooks", out)
        code, out, _ = run("list")
        self.assertEqual(code, 0)
        self.assertIn("ID-001", out)
        self.assertIn("SOC Operations and Agent Performance", out)

    def test_build_into_another_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            code, out, err = run("build", "--out", folder, "--enabled")
            self.assertEqual((code, err), (0, ""))
            template = json.loads((Path(folder) / "Detection-rules" / "deploy" / "all-rules.json").read_text(encoding="utf-8"))
            self.assertTrue(all(resource["properties"]["enabled"] for resource in template["resources"]))
            self.assertTrue((Path(folder) / "Workbooks" / "deploy" / "all-workbooks.json").exists())
        # The repository copy is untouched and still has every rule disabled.
        self.assertEqual(run("check")[0], 0)

    def test_enabled_without_out_is_refused(self):
        code, _, err = run("build", "--enabled")
        self.assertEqual(code, 2)
        self.assertIn("--enabled needs --out", err)
        code, _, err = run("build", "--out", " ")
        self.assertEqual(code, 2)

    def test_export_queries(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "queries.json"
            code, _, _ = run("export-queries", str(target))
            self.assertEqual(code, 0)
            self.assertGreater(len(json.loads(target.read_text(encoding="utf-8"))), 100)
        code, _, err = run("export-queries", str(Path(folder) / "gone" / "queries.json"))
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_unknown_command(self):
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            cli.main(["deploy"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
