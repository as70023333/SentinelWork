import unittest

from sentinel_content import kql

SCHEMA = {
    "SigninLogs": {"TimeGenerated": "datetime", "UserPrincipalName": "string", "IPAddress": "string",
                   "ResultType": "string", "LocationDetails": "dynamic", "UserAgent": "string", "UserId": "string"},
    "DeviceEvents": {"TimeGenerated": "datetime", "DeviceName": "string", "ActionType": "string"},
}  # fmt: skip


def problems(query, workbook=False):
    return kql.check_names(query, SCHEMA, workbook=workbook)


class TokenizerTests(unittest.TestCase):
    def test_comments_and_whitespace_are_dropped(self):
        tokens = kql.tokenize("SigninLogs // the table\n| take 5")
        self.assertEqual([t.text for t in tokens], ["SigninLogs", "|", "take", "5"])
        self.assertEqual(tokens[-1].line, 2)

    def test_a_url_inside_a_string_is_not_a_comment(self):
        tokens = kql.tokenize('print "https://example.com/a" // real comment')
        self.assertEqual(tokens[1].text, '"https://example.com/a"')
        self.assertEqual(len(tokens), 2)

    def test_string_forms(self):
        for text in ('"a \\" b"', "'it''s'", '@"c:\\dir\\"', "@'\"'", "'a \\' b'"):
            with self.subTest(text=text):
                tokens = kql.tokenize(f"print {text}")
                self.assertEqual(tokens[-1].kind, "string")
                self.assertEqual("".join(t.text for t in tokens[1:]), text)

    def test_hyphenated_operators_are_one_token(self):
        tokens = kql.tokenize("T | mv-expand x | project-away y | make-series z")
        self.assertIn("mv-expand", [t.text for t in tokens])
        self.assertIn("project-away", [t.text for t in tokens])
        self.assertIn("make-series", [t.text for t in tokens])

    def test_subtraction_is_not_swallowed_by_a_hyphenated_keyword(self):
        self.assertEqual([t.text for t in kql.tokenize("project - away")], ["project", "-", "away"])

    def test_timespans_are_numbers(self):
        tokens = kql.tokenize("ago(14d) 1.5 30m")
        self.assertEqual([t.kind for t in tokens if t.text in ("14d", "1.5", "30m")], ["number"] * 3)

    def test_unterminated_string_is_an_error(self):
        with self.assertRaises(kql.KqlError):
            kql.tokenize('print "never closed')

    def test_strip_comments_keeps_the_query(self):
        text = "// Title: x\n// more\nSigninLogs\n| where UserAgent has \"//\" // why\n| take 1\n"
        self.assertEqual(kql.strip_comments(text), 'SigninLogs\n| where UserAgent has "//"\n| take 1')

    def test_strip_comments_leaves_no_empty_line_behind(self):
        # The Logs editor ends a query at an empty line, so a removed comment must take its line with it.
        text = "SigninLogs\n// why\n| where UserId == 'a'\n    // indented note\n| take 1 // tail\n// end\n"
        self.assertEqual(kql.strip_comments(text), "SigninLogs\n| where UserId == 'a'\n| take 1")
        self.assertEqual(kql.strip_comments("a\n\nb"), "a\n\nb")  # a real empty line is kept, and reported elsewhere
        self.assertEqual(kql.strip_comments("// only a comment"), "")


class NameCheckTests(unittest.TestCase):
    def test_a_valid_query_has_no_problems(self):
        query = """
        let Limit = 5;
        SigninLogs
        | where TimeGenerated > ago(1h) and ResultType in ("50126", "50053")
        | summarize Attempts = count(), Users = dcount(UserPrincipalName) by IPAddress
        | where Attempts >= Limit
        | project IPAddress, Attempts, Users
        """
        self.assertEqual(problems(query), [])

    def test_a_misspelt_column_is_reported_with_its_line(self):
        found = problems("SigninLogs\n| where UserPrincipleName == 'a'")
        self.assertEqual(len(found), 1)
        self.assertIn("line 2", found[0])
        self.assertIn("UserPrincipleName", found[0])

    def test_a_column_from_another_table_is_reported(self):
        self.assertTrue(any("DeviceName" in p for p in problems("SigninLogs | where DeviceName == 'x'")))

    def test_a_column_is_accepted_once_its_table_is_read(self):
        query = "SigninLogs | join kind=inner (DeviceEvents | project DeviceName, IPAddress = ActionType) on IPAddress"
        self.assertEqual(problems(query), [])

    def test_an_unknown_function_is_reported(self):
        self.assertEqual(problems("SigninLogs | extend x = tosting(UserId)"), ["line 1: unknown function tosting()"])

    def test_a_function_without_brackets_is_reported(self):
        self.assertTrue(any("without ()" in p for p in problems("SigninLogs | summarize count by IPAddress, dcount")))

    def test_properties_of_dynamic_values_are_not_columns(self):
        self.assertEqual(problems("SigninLogs | extend Country = tostring(LocationDetails.countryOrRegion)"), [])

    def test_names_defined_by_parse_and_datatable(self):
        query = """
        let Known = datatable(Address:string, Owner:string) ["1.2.3.4", "vpn"];
        SigninLogs
        | parse UserAgent with * "Chrome/" Version:string " " Rest
        | join kind=leftouter Known on $left.IPAddress == $right.Address
        | project Version, Rest, Owner, Address
        """
        self.assertEqual(problems(query), [])

    def test_parse_does_not_define_names_after_the_next_pipe(self):
        found = problems('SigninLogs | parse UserAgent with * "x" Version | project Version, Missing')
        self.assertEqual(found, ["line 1: unknown name Missing (tables read: SigninLogs)"])

    def test_the_right_hand_copy_of_a_join_column(self):
        query = "SigninLogs | join kind=inner (SigninLogs | project UserId) on UserId | project UserId, UserId1"
        self.assertEqual(problems(query), [])
        self.assertTrue(problems("SigninLogs | project UserId1"))

    def test_unbalanced_brackets(self):
        self.assertEqual(problems("SigninLogs | where (ResultType == '0'"), ["line 1: '(' is never closed"])
        self.assertEqual(problems("SigninLogs | take 1)"), ["line 1: closing ')' without an opening one"])
        self.assertEqual(problems("SigninLogs\n| where (UserId == 'x']"), ["line 2: ']' closes the '(' opened on line 2"])

    def test_reported_lines_can_be_file_lines(self):
        query = "SigninLogs\n| where Nope == 1"
        self.assertEqual(kql.check_names(query, SCHEMA)[0][:7], "line 2:")
        self.assertEqual(kql.check_names(query, SCHEMA, first_line=20)[0][:8], "line 21:")
        self.assertEqual(kql.check_names('SigninLogs | where a == "x', SCHEMA, first_line=20)[0][:8], "line 20:")

    def test_a_query_that_reads_no_table(self):
        self.assertTrue(any("does not read any table" in p for p in problems("print 1")))

    def test_placeholders_only_in_workbook_queries(self):
        query = "SigninLogs | summarize Total = count() by bin(TimeGenerated, {TimeRange:grain})"
        self.assertEqual(problems(query, workbook=True), [])
        self.assertTrue(problems(query))

    def test_an_unknown_placeholder_is_reported(self):
        found = problems("SigninLogs | where TimeGenerated {TimeRange}", workbook=True)
        self.assertEqual(len(found), 1)
        self.assertIn("{TimeRange}", found[0])

    def test_has_placeholder(self):
        self.assertTrue(kql.has_placeholder("T | where a > {TimeRange:start}"))
        self.assertTrue(kql.has_placeholder("T | where a in ({Users})"))
        self.assertFalse(kql.has_placeholder('let m = dynamic({"a": "b"}); T | where x == "{y}" // {z}'))
        self.assertFalse(kql.has_placeholder("let f = (x:string) { x }; T | take 1"))

    def test_every_placeholder_becomes_valid_kql(self):
        query = "SigninLogs | where TimeGenerated between ({TimeRange:start} .. {TimeRange:end}) | summarize Total = count() by bin(TimeGenerated, {TimeRange:grain})"
        self.assertEqual(problems(query, workbook=True), [])
        self.assertNotIn("{", kql.fill_placeholders(query))

    def test_lookback_of_literals_names_and_now(self):
        day = 86400
        self.assertEqual(kql.lookback("T | where a > ago(1h) and b between (ago(14d) .. ago(30m))"), (14 * day, []))
        self.assertEqual(kql.lookback("let Window = 30d; T | where a > ago(Window)"), (30 * day, []))
        self.assertEqual(kql.lookback("T | where a > now() - 30d"), (30 * day, []))
        self.assertEqual(kql.lookback("T | where a > ago(1.5d)"), (1.5 * day, []))
        self.assertEqual(kql.lookback('// ago(30d)\nT | where a == "ago(99d)" | take 1'), (0, []))
        self.assertEqual(kql.lookback("T | where a < now() and b.ago(c) == 1")[1], [])

    def test_computing_an_age_is_not_a_lookback(self):
        for query in ("T | extend Age = toint((now() - LastRecord) / 1h)", "T | summarize Oldest = max((now() - Created) / 1d)",
                      "T | where a > ago(2h) | extend Hours = datetime_diff('hour', now(), a)",
                      "T | where a < b - 1h and a > ago(3h)"):  # fmt: skip
            with self.subTest(query=query):
                self.assertEqual(kql.lookback(query)[1], [])

    def test_arrival_windows(self):
        query = "T | where ingestion_time() > ago(65m) and ingestion_time() <= ago(5m) | union (T | where ingestion_time() <= ago(65m))"
        self.assertEqual(kql.arrival_windows(query), ([(3900.0, 300.0)], [3900.0], []))
        self.assertEqual(kql.arrival_windows("let Start = 65m; T\n| where ingestion_time() > ago(Start)\n    and ingestion_time() <= ago(5m)")[0], [(3900.0, 300.0)])
        self.assertEqual(kql.arrival_windows("T | take 1 // ingestion_time()"), ([], [], []))
        for query in ("T | where ingestion_time() > ago(1h)", "T | extend Arrived = ingestion_time()",
                      "T | where ingestion_time() between (ago(65m) .. ago(5m))"):  # fmt: skip
            with self.subTest(query=query):
                self.assertEqual(len(kql.arrival_windows(query)[2]), 1)

    def test_lookback_that_cannot_be_read_is_reported(self):
        for query in ("T | where a > ago(Window)", "T | where a > ago(1h + 30m)", "T | where a > ago(time(30d))",
                      "T | where a > ago(30days)", "T | where a > now(-30d)", "T | where a > ago(1h) - 30d",
                      "T | where a > now() - 2 * 7d", "T | where a > now() - (30d)", "T | where a > now() - 1h - 30d",
                      "T | where a > startofmonth(now())", "T | where a > datetime_add('day', -30, now())",
                      "T | where a > now() - time(30d)", "let W = 1h; let W2 = W * 100; T | where a > now() - W2",
                      "let Back = ago(1h); T | where a > Back - 30d", "T | where a > bin(ago(1h), 30d)"):  # fmt: skip
            with self.subTest(query=query):
                seconds, unclear = kql.lookback(query)
                self.assertEqual(len(unclear), 1, unclear)
                self.assertTrue(unclear[0].startswith("line 1:"))

    def test_a_schema_file_of_the_wrong_shape_is_refused(self):
        import json
        import tempfile
        from pathlib import Path

        for content in ([], {"tables": {}}, {"tables": []}, {"tables": {"T": ["a"]}}, {"tables": {"T": {"a": 1}}}):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "tables.json"
                path.write_text(json.dumps(content), encoding="utf-8")
                with self.assertRaises(ValueError):
                    kql.load_schema(path)

    def test_the_real_schema_loads(self):
        schema = kql.load_schema()
        self.assertIn("SigninLogs", schema)
        self.assertEqual(schema["SigninLogs"]["LocationDetails"], "dynamic")
        for table, columns in schema.items():
            self.assertIn("TimeGenerated", columns, table)


if __name__ == "__main__":
    unittest.main()
