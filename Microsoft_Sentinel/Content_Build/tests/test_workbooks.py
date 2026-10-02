import json
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
                    self.assertEqual(content["timeContextFromParameter"], workbooks.TIME_PARAMETER)
                    self.assertEqual(content["queryType"], 0)
                    self.assertEqual(content["resourceType"], "microsoft.operationalinsights/workspaces")
                    self.assertIn(content["visualization"], ("tiles", "table", *workbooks.CHARTS))
                    self.assertTrue(content["title"])
                    self.assertNotIn("render", kql.names_in(content["query"], workbook=True))
                    self.assertTrue(1 <= int(item["customWidth"]) <= 100)
                self.assertEqual(json.loads(workbooks.gallery_text(book, RULES)), gallery)

    def test_output_is_the_same_every_time(self):
        for book in self.books:
            self.assertEqual(workbooks.gallery_text(book, RULES), workbooks.gallery_text(book, RULES))

    def test_the_detections_tab_lists_exactly_the_rules_of_the_area(self):
        for book in self.books:
            with self.subTest(book=book.file):
                own = [rule for rule in RULES if rule.area == book.area]
                coverage = workbooks.detection_items(own)[1].query
                for rule in RULES:
                    self.assertEqual(workbooks.kql_string(rule.title) in coverage, rule in own, rule.id)
                    self.assertEqual(f'"{rule.id}"' in coverage, rule in own, rule.id)

    def test_every_generated_query_reads_only_incident_and_alert_tables(self):
        for label, query in workbooks.workbook_queries(self.books[0], RULES):
            if label.startswith(workbooks.DETECTIONS_TAB):
                used = kql.tables_used(kql.tokenize(kql.fill_placeholders(query)), SCHEMA)
                self.assertLessEqual(set(used), set(workbooks.DETECTION_TABLES), label)


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
            (changed("width = 50", "width = 5"), "width must be"),
            (changed("width = 50", 'width = "half"'), "width must be"),
            (changed("by IPAddress", "by IPAdress"), "unknown name IPAdress"),
            (changed("{TimeRange:grain}", "{Grain}"), "unknown workbook placeholder"),
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

    def test_a_chart_must_not_render_itself(self):
        text = VALID + "\n[[tab.item]]\nkind = \"barchart\"\ntitle = \"Chart\"\nquery = '''\nSigninLogs\n| summarize Total = count() by IPAddress\n| render barchart\n'''\n"
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
