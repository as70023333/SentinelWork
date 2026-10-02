import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sentinel_content import kql, rules, workbooks

SCHEMA = kql.load_schema()
RULES = rules.load_rules()

VALID = """\
name = "Test Sign-ins"
file = "TestSignIns"
area = "identity-sign-ins"
summary = "A workbook used by the tests"
tables = ["SigninLogs"]
intro = "Sign-ins for the tests."

[[tab]]
name = "Overview"

[[tab.item]]
kind = "text"
text = "Some words."

[[tab.item]]
kind = "tiles"
title = "Totals"
label = "Metric"
value = "Value"
query = '''
SigninLogs
| summarize Value = count()
| extend Metric = "Sign-ins"
'''

[[tab.item]]
kind = "table"
title = "By address"
width = 50
bars = ["Attempts"]
query = '''
SigninLogs
| summarize Attempts = count() by IPAddress, bin(TimeGenerated, {TimeRange:grain})
'''

[[tab.item]]
kind = "piechart"
title = "By result"
width = 50
query = '''
SigninLogs
| summarize Total = count() by ResultType
'''
"""


def load(text, name="test-sign-ins.toml"):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / name
        path.write_text(text, encoding="utf-8")
        return workbooks.parse_workbook(path)


def changed(old, new):
    assert old in VALID, old
    return VALID.replace(old, new)


def walk(items):
    for item in items:
        yield item
        if item["type"] == 12:
            yield from walk(item["content"]["items"])


class RepositoryWorkbookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.books = workbooks.load_workbooks()

    def test_every_workbook_passes_the_checks(self):
        self.assertEqual(workbooks.check_workbooks(self.books, RULES, SCHEMA), [])

    def test_one_workbook_for_each_area(self):
        self.assertEqual([book.area for book in self.books], list(rules.AREAS))

    def test_gallery_structure(self):
        for book in self.books:
            with self.subTest(book=book.file):
                gallery = workbooks.gallery(book, RULES)
                self.assertEqual(gallery["version"], "Notebook/1.0")
                self.assertEqual(gallery["$schema"], workbooks.WORKBOOK_SCHEMA)
                self.assertNotIn("fallbackResourceIds", gallery)  # no subscription or workspace id is baked in
                items = list(walk(gallery["items"]))
                names = [item["name"] for item in items]
                self.assertEqual(len(set(names)), len(names))
                tabs = [link["subTarget"] for item in items if item["type"] == 11 for link in item["content"]["links"]]
                self.assertEqual(tabs[-1], workbooks.DETECTIONS_TAB)
                groups = [item for item in gallery["items"] if item["type"] == 12]
                self.assertEqual([group["conditionalVisibility"]["value"] for group in groups], tabs)
                for group in groups:
                    self.assertEqual(group["conditionalVisibility"]["parameterName"], workbooks.TAB_PARAMETER)
                parameters = [p for item in items if item["type"] == 9 for p in item["content"]["parameters"]]
                self.assertEqual([p["name"] for p in parameters], [workbooks.TIME_PARAMETER])
                self.assertIn(parameters[0]["value"], parameters[0]["typeSettings"]["selectableValues"])
                queries = [item for item in items if item["type"] == 3]
                self.assertGreaterEqual(len(queries), 12)
                for item in queries:
                    content = item["content"]
                    if "timeContextFromParameter" in content:
                        self.assertEqual(content["timeContextFromParameter"], workbooks.TIME_PARAMETER)
                        self.assertEqual(content["timeContext"], {"durationMs": 0})
                    self.assertEqual(content["queryType"], 0)
                    self.assertEqual(content["resourceType"], "microsoft.operationalinsights/workspaces")
                    self.assertIn(content["visualization"], ("tiles", "table", *workbooks.CHARTS))
                    self.assertTrue(content["title"])
                    self.assertNotIn("render", kql.names_in(content["query"], workbook=True))
                    self.assertTrue(1 <= int(item["customWidth"]) <= 100)
                self.assertEqual(json.loads(workbooks.gallery_text(book, RULES)), gallery)

    def test_output_is_the_same_in_another_process(self):
        # Set and dictionary ordering can differ between runs; a build must not depend on it.
        code = ("import hashlib, json; from sentinel_content import build; r, b, s = build.load_all(); "
                "print(hashlib.sha256(json.dumps(sorted((str(p), t) for p, t in "
                "build.generated_files(r, b).items())).encode()).hexdigest())")  # fmt: skip
        root = Path(__file__).resolve().parent.parent
        digests = set()
        for seed in ("0", "1", "4242"):
            result = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True,
                                    env={**os.environ, "PYTHONHASHSEED": seed}, check=True)  # fmt: skip
            digests.add(result.stdout.strip())
        self.assertEqual(len(digests), 1)

    def test_committed_workbooks_are_recognised_as_generated_and_hand_made_ones_are_not(self):
        for book in self.books:
            self.assertTrue(workbooks.is_generated_workbook(workbooks.WORKBOOKS_DIR / f"{book.file}.json"), book.file)
        for name in ("AzureCost.json", "DataConnectorCost.json", "DataIngestionLatency.json", "missing.json"):
            self.assertFalse(workbooks.is_generated_workbook(workbooks.WORKBOOKS_DIR / name), name)

    def test_fixed_ranges_are_only_used_where_the_picker_must_not_apply(self):
        fixed = []
        for book in self.books:
            for item in walk(workbooks.gallery(book, RULES)["items"]):
                if item["type"] == 3 and "timeContextFromParameter" not in item["content"]:
                    self.assertGreater(item["content"]["timeContext"]["durationMs"], 0)
                    fixed.append(item["content"]["title"])
        self.assertTrue(fixed)
        self.assertTrue(all("days" in title for title in fixed), fixed)  # the title must say so

    def test_the_detections_tab_lists_exactly_the_rules_of_the_area(self):
        for book in self.books:
            with self.subTest(book=book.file):
                own = [rule for rule in RULES if rule.area == book.area]
                coverage = workbooks.detection_items(own)[1].query
                for rule in RULES:
                    self.assertEqual(workbooks.kql_string(rule.title) in coverage, rule in own, rule.id)
                    self.assertEqual(f'"{rule.id}"' in coverage, rule in own, rule.id)

    def test_every_generated_query_reads_only_incident_and_alert_tables(self):
        checked = 0
        for book in self.books:
            for label, query in workbooks.workbook_queries(book, RULES):
                if label.startswith(workbooks.DETECTIONS_TAB):
                    used = kql.tables_used(kql.tokenize(kql.fill_placeholders(query)), SCHEMA)
                    self.assertLessEqual(set(used), set(workbooks.DETECTION_TABLES), label)
                    checked += 1
        self.assertEqual(checked, 4 * len(self.books))

    def test_incidents_are_matched_by_rule_identifier_as_well_as_by_name(self):
        own = [rule for rule in RULES if rule.area == "identity-sign-ins"]
        incidents = workbooks.detection_items(own)[-1].query
        for rule in own:
            self.assertIn(rule.guid, incidents)
        self.assertIn("RelatedAnalyticRuleIds", incidents)


class SourceTests(unittest.TestCase):
    def check(self, text):
        return workbooks.check_workbook(load(text), RULES, SCHEMA)

    def test_the_valid_example_is_valid(self):
        book = load(VALID)
        self.assertEqual(workbooks.check_workbook(book, RULES, SCHEMA), [])
        self.assertEqual(book.key, "test-sign-ins")
        self.assertEqual([tab.name for tab in workbooks.all_tabs(book, RULES)], ["Overview", "Detections"])

    def test_files_that_cannot_be_read(self):
        for text, expected in (
            ("name = ", "not valid TOML"),
            (changed('summary = "A workbook used by the tests"\n', ""), "missing 'summary'"),
            (changed('area = "identity-sign-ins"', 'area = "identity-sign-ins"\ncolour = "blue"'), "unknown setting"),
            (changed('kind = "tiles"', 'kind = "gauge"'), "kind 'gauge'"),
            (changed('kind = "text"\ntext = "Some words."', 'kind = "text"\ntext = "Some words."\nbars = ["x"]'), "cannot have bars"),
            (VALID.split("[[tab.item]]")[0], "needs a name and at least one"),
            (changed('tables = ["SigninLogs"]', 'tables = [1]'), "tables must be a list of names"),
            (changed('tables = ["SigninLogs"]', 'tables = "SigninLogs"'), "tables must be a list of names"),
            (changed('bars = ["Attempts"]', 'bars = "Attempts"'), "bars must be a list of names"),
            (changed('title = "Totals"', "title = 5"), "title must be text"),
            (changed("width = 50\nbars", 'width = "half"\nbars'), "width must be a whole number"),
            (changed("width = 50\nbars", "width = true\nbars"), "width must be a whole number"),
            (changed('bars = ["Attempts"]', 'bars = ["Attempts"]\nrows = "many"'), "rows must be a whole number"),
            (changed('title = "By result"', 'title = "By result"\ncolours = ["green"]'), "colours must look like"),
            (changed('name = "Test Sign-ins"', "name = 7"), "name must be text"),
            (VALID.split("[[tab.item]]")[0] + 'item = ["a"]\n', "must be a table of settings"),
            (VALID.split("[[tab.item]]")[0] + 'item = "abc"\n', "needs a name and at least one"),
            (VALID.split("[[tab]]")[0] + 'tab = "Overview"\n', "written as [[tab]] sections"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(workbooks.WorkbookError) as raised:
                    load(text)
                self.assertIn(expected, str(raised.exception))

    def test_each_mistake_is_reported(self):
        cases = (
            (changed('area = "identity-sign-ins"', 'area = "somewhere"'), "area 'somewhere'"),
            (changed('file = "TestSignIns"', 'file = "Test Sign-ins.json"'), "letters and digits only"),
            (changed('tables = ["SigninLogs"]', 'tables = ["SigninLogs", "AuditLogs"]'), "no query reads them"),
            (changed('tables = ["SigninLogs"]', 'tables = ["AuditLogs"]'), "queries read SigninLogs"),
            (changed('tables = ["SigninLogs"]', 'tables = ["SigninLogs", "Nope"]'), "'Nope' is not in the schema"),
            (changed('bars = ["Attempts"]', 'bars = ["Tries"]'), "'Tries' is formatted but never appears"),
            (changed('label = "Metric"', 'label = "Name"'), "'Name' is formatted but never appears"),
            (changed("width = 50\nbars", "width = 5\nbars"), "width must be"),
            (changed("width = 50\nbars", "width = 60\nbars"), "the row before it only fills 60 of 100"),
            (changed("width = 50\nquery", "width = 30\nquery"), "the last row only fills 80 of 100"),
            (changed('title = "By result"', 'title = "By result"\ncolours = { Success = "chartreuse" }'), "colour 'chartreuse'"),
            (changed('title = "By result"', 'title = "By {Range}"'), "a title must not contain"),
            (changed('title = "By result"', 'title = "By result"\nrange = "1y"'), "range '1y'"),
            (changed('bars = ["Attempts"]', 'bars = ["Attempts"]\nrows = 0'), "rows must be 1 to 10000"),
            (changed('name = "Overview"', 'name = "detections"'), "'Detections' is generated"),
            (changed('file = "TestSignIns"', 'file = "AzureCost"'), "would overwrite Workbooks/AzureCost.json"),
            (changed('file = "TestSignIns"', 'file = "DataIngestionLatency"'), "would overwrite"),
            (changed("by IPAddress", "by IPAdress"), "unknown name IPAdress"),
            (changed("{TimeRange:grain}", "{Grain}"), "unknown workbook placeholder"),
            (changed("by IPAddress, bin", "by (IPAddress], bin"), "closes the '('"),
            (changed('name = "Overview"', 'name = "Detections"'), "'Detections' is generated"),
            (changed('title = "Totals"\n', ""), "needs a title"),
            (changed('text = "Some words."', 'text = " "'), "needs text"),
            (changed('intro = "Sign-ins for the tests."', 'intro = "Sign-ins."\ndefault_range = "1y"'), "default_range"),
            (changed('bars = ["Attempts"]', 'bars = ["Attempts"]\npalette = "rainbow"'), "palette must be"),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                problems = self.check(text)
                self.assertTrue(any(expected in problem for problem in problems), f"{expected!r} not in {problems}")

    def test_tab_names_that_only_differ_in_case_or_spacing_clash(self):
        text = VALID + '\n[[tab]]\nname = "over-view"\n[[tab.item]]\nkind = "text"\ntext = "x"\n'
        self.assertFalse(any("tab names must be unique" in p for p in self.check(text)))
        text = VALID + '\n[[tab]]\nname = "OVERVIEW"\n[[tab.item]]\nkind = "text"\ntext = "x"\n'
        self.assertTrue(any("tab names must be unique" in p for p in self.check(text)))
        text = VALID + '\n[[tab]]\nname = "Over view"\n[[tab.item]]\nkind = "text"\ntext = "x"\n[[tab]]\nname = "Over-View"\n[[tab.item]]\nkind = "text"\ntext = "x"\n'
        self.assertTrue(any("tab names must be unique" in p for p in self.check(text)))

    def test_a_file_with_a_byte_order_mark_and_one_that_is_not_utf8(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test-sign-ins.toml"
            path.write_bytes(b"\xef\xbb\xbf" + VALID.encode("utf-8"))
            self.assertEqual(workbooks.check_workbook(workbooks.parse_workbook(path), RULES, SCHEMA), [])
            path.write_bytes(VALID.encode("utf-8").replace(b"Totals", b"Tot\xff\xfe"))
            with self.assertRaises(workbooks.WorkbookError) as raised:
                workbooks.parse_workbook(path)
            self.assertIn("test-sign-ins.toml", str(raised.exception))

    def test_a_fixed_range_replaces_the_time_range_picker_for_that_item(self):
        book = load(changed('title = "By result"', 'title = "By result (last 90 days)"\nrange = "90d"'))
        self.assertEqual(workbooks.check_workbook(book, RULES, SCHEMA), [])
        items = list(walk(workbooks.gallery(book, RULES)["items"]))
        chart = next(item for item in items if item["type"] == 3 and item["content"]["visualization"] == "piechart")
        self.assertEqual(chart["content"]["timeContext"], {"durationMs": 90 * 86400 * 1000})
        self.assertNotIn("timeContextFromParameter", chart["content"])

    def test_a_chart_must_not_render_itself(self):
        text = changed("| summarize Total = count() by ResultType", "| summarize Total = count() by ResultType\n| render piechart")
        self.assertTrue(any("leave out 'render'" in problem for problem in self.check(text)))

    def test_table_formatters_in_the_gallery(self):
        text = changed('bars = ["Attempts"]', 'bars = ["Attempts"]\nseverity = "IPAddress"\nlink = "TimeGenerated"\nhide = ["Attempts"]\nrows = 10')
        book = load(text)
        self.assertEqual(workbooks.check_workbook(book, RULES, SCHEMA), [])
        items = list(walk(workbooks.gallery(book, RULES)["items"]))
        table = next(item for item in items if item["type"] == 3 and item["content"]["title"] == "By address")
        self.assertEqual(table["customWidth"], "50")
        grid = table["content"]["gridSettings"]
        self.assertEqual(grid["rowLimit"], 10)
        self.assertEqual([f["formatter"] for f in grid["formatters"]], [18, 4, 7, 5])
        thresholds = grid["formatters"][0]["formatOptions"]["thresholdsGrid"]
        self.assertEqual([t["thresholdValue"] for t in thresholds], ["High", "Medium", "Low", "Informational", None])
        self.assertIn("\r\n", table["content"]["query"])
        tiles = next(item for item in items if item["type"] == 3 and item["content"]["visualization"] == "tiles")
        self.assertEqual(tiles["content"]["tileSettings"]["titleContent"]["columnMatch"], "Metric")
        self.assertEqual(tiles["content"]["tileSettings"]["leftContent"]["columnMatch"], "Value")

    def test_kql_string_escapes_quotes_and_backslashes(self):
        self.assertEqual(workbooks.kql_string('a "b" c\\d'), '"a \\"b\\" c\\\\d"')
        tokens = kql.tokenize("print " + workbooks.kql_string('a "b" c\\d'))
        self.assertEqual(len(tokens), 2)

    def test_duplicates_and_missing_areas_across_workbooks(self):
        book = load(VALID)
        problems = workbooks.check_workbooks([book, book], RULES, SCHEMA)
        self.assertTrue(any("workbook file 'testsignins' is used more than once" in p for p in problems))
        self.assertTrue(any("no workbook for area(s)" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
