import json
import tempfile
import unittest
import uuid
from pathlib import Path

from sentinel_content import kql, rules

SCHEMA = kql.load_schema()

VALID = """\
// Title: Many failed sign-ins from one address
// Id: ID-900
// Severity: Medium
// Tactics: CredentialAccess
// Techniques: T1110
// Sub-techniques: T1110.003
// Tables: SigninLogs
// Frequency: PT1H
// Period: PT1H
// Entities: IP(Address=IPAddress)
// Custom details: Attempts
// Description: One address failed to sign in to many accounts within the hour, which is what a
//   password spray looks like from the directory's side.
// False positives: A shared office address after a password change wave.
// Tuning: Raise the threshold for large offices behind one address.
// Response: Block the address and check whether any sign-in from it succeeded.
// References: https://learn.microsoft.com/entra/
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize Attempts = count() by IPAddress
| where Attempts > 20
"""


def check(text, name="ID-900-test.kql", area="identity-sign-ins"):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / area / name
        path.parent.mkdir()
        path.write_text(text, encoding="utf-8")
        rule = rules.parse_rule(path)
        return rule, rules.check_rule(rule, SCHEMA)


def changed(old, new):
    assert old in VALID, old
    return VALID.replace(old, new)


class RepositoryRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = rules.load_rules()

    def test_every_rule_passes_the_checks(self):
        self.assertEqual(rules.check_rules(self.rules, SCHEMA), [])

    def test_every_area_has_rules_numbered_without_gaps(self):
        for area, details in rules.AREAS.items():
            ids = [rule.id for rule in self.rules if rule.area == area]
            self.assertTrue(ids, f"no rules in {area}")
            self.assertEqual(ids, [f"{details['prefix']}-{n:03d}" for n in range(1, len(ids) + 1)], area)

    def test_no_rule_file_is_left_out(self):
        self.assertEqual(rules.stray_rule_files(), [])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("ID-900-loose.kql", "identity-sign-ins/ID-901-ok.kql", "identity-sign-ins/ID-902-upper.KQL",
                         "identity-sign-ins/old/ID-903-nested.kql"):  # fmt: skip
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text("x", encoding="utf-8")
            stray = rules.stray_rule_files(root)
            self.assertEqual(len(stray), 3)
            self.assertFalse(any("ID-901" in line for line in stray))

    def test_a_rule_keeps_its_identifier(self):
        # Sentinel knows each rule by this GUID. If it changed, a redeployment would create a second
        # copy of every rule next to the first, so the value is pinned here.
        self.assertEqual(self.rules[0].id, "ID-001")
        self.assertEqual(self.rules[0].guid, "07dec7c4-739b-532d-af40-42fb21e26b80")

    def test_event_rules_tolerate_late_data(self):
        # A rule that looks for events must pick them by arrival time and read further back than it
        # runs; otherwise an event that reaches the workspace late is never evaluated. Rules that
        # report a state (a table gone quiet, an incident left open, a noisy rule) are the exception.
        state_rules = {"SO-001", "SO-003", "SO-004"}
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                if rule.id in state_rules:
                    continue
                self.assertIn("ingestion_time()", rule.query)
                self.assertGreater(rules.duration_seconds(rule.period), rules.duration_seconds(rule.frequency))

    def test_no_query_has_an_empty_line_or_a_comment_left_in_the_template(self):
        for rule in self.rules:
            query = rules.rule_properties(rule, enabled=False)["query"]
            self.assertNotIn("\n\n", query, rule.id)
            self.assertNotIn("//", query.replace("https://", ""), rule.id)

    def test_rule_guids_are_stable_and_unique(self):
        guids = [rule.guid for rule in self.rules]
        self.assertEqual(len(set(guids)), len(guids))
        for guid in guids:
            uuid.UUID(guid)
        self.assertEqual(guids, [rule.guid for rule in rules.load_rules()])

    def test_properties_have_what_the_api_requires(self):
        required = {"displayName", "enabled", "query", "queryFrequency", "queryPeriod", "severity",
                    "suppressionDuration", "suppressionEnabled", "triggerOperator", "triggerThreshold"}  # fmt: skip
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                properties = rules.rule_properties(rule, enabled=False)
                self.assertLessEqual(required, set(properties))
                self.assertIs(properties["enabled"], False)
                self.assertIn(properties["severity"], rules.SEVERITIES)
                self.assertNotIn("//", properties["query"].split("\n")[0])
                self.assertLessEqual(len(properties["description"]), rules.MAX_DESCRIPTION)
                self.assertIn(rule.id, properties["description"])
                json.dumps(properties)
                grouping = properties["incidentConfiguration"]["groupingConfiguration"]
                self.assertIn(grouping["matchingMethod"], ("AllEntities", "Selected"))
                if grouping["matchingMethod"] == "Selected":
                    self.assertTrue(grouping["groupByEntities"] or grouping["groupByCustomDetails"])
                for mapping in properties.get("entityMappings", []):
                    self.assertIn(mapping["entityType"], rules.ENTITY_IDENTIFIERS)
                    for field in mapping["fieldMappings"]:
                        self.assertEqual(set(field), {"identifier", "columnName"})

    def test_a_rule_without_entities_has_no_empty_mapping_list(self):
        rule = next(rule for rule in self.rules if rule.id == "SO-001")
        properties = rules.rule_properties(rule, enabled=True)
        self.assertNotIn("entityMappings", properties)
        self.assertIs(properties["enabled"], True)
        self.assertEqual(properties["incidentConfiguration"]["groupingConfiguration"]["groupByCustomDetails"], ["DataType"])

    def test_operational_rules_have_no_tactics(self):
        operational = [rule for rule in self.rules if rule.area == "soc-operations"]
        self.assertTrue(operational)
        for rule in operational:
            properties = rules.rule_properties(rule, enabled=False)
            self.assertEqual(properties["tactics"], [], rule.id)
            self.assertEqual(properties["techniques"], [], rule.id)

    def test_technique_table_only_uses_known_tactics(self):
        for technique, tactics in rules.TECHNIQUE_TACTICS.items():
            self.assertRegex(technique, r"^T\d{4}$")
            self.assertLessEqual(set(tactics), set(rules.TACTICS), technique)


class HeaderTests(unittest.TestCase):
    def test_the_valid_example_is_valid(self):
        rule, problems = check(VALID)
        self.assertEqual(problems, [])
        self.assertEqual(rule.title, "Many failed sign-ins from one address")
        self.assertIn("password spray looks like", rule.description)
        self.assertNotIn("//", rule.description)
        self.assertTrue(rule.query.startswith("SigninLogs"))
        self.assertEqual(rule.entities, (("IP", (("Address", "IPAddress"),)),))
        self.assertEqual(rule.custom_details, (("Attempts", "Attempts"),))
        self.assertEqual(rule.output_columns, ["IPAddress", "Attempts"])

    def test_unknown_duplicate_and_missing_fields(self):
        for text, expected in (
            (changed("// Severity: Medium", "// Severity: Medium\n// Colour: blue"), "unknown header field"),
            (changed("// Severity: Medium", "// Severity: Medium\n// Severity: High"), "appears twice"),
            (changed("// Tuning: Raise the threshold for large offices behind one address.\n", ""), "missing header field"),
            (changed("// Severity: Medium", "//Severity Medium"), "not 'Key: value'"),
            (changed("// Entities: IP(Address=IPAddress)", "// Entities: IP Address"), "Type(Identifier=Column"),
            (changed("// Entities: IP(Address=IPAddress)", "// Entities: IP(Address)"), "Identifier=Column pairs"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Trigger: MoreThan"), "Trigger must look like"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Trigger: GreaterThan \u00b2"), "Trigger must look like"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: sometimes"), "Incidents"),
        ):
            with self.subTest(expected=expected):
                with self.assertRaises(rules.RuleError) as raised:
                    check(text)
                self.assertIn(expected, str(raised.exception))

    def test_durations(self):
        self.assertEqual(rules.duration_seconds("PT5M"), 300)
        self.assertEqual(rules.duration_seconds("PT1H"), 3600)
        self.assertEqual(rules.duration_seconds("P1D"), 86400)
        self.assertEqual(rules.duration_seconds("P2DT1H30M"), 2 * 86400 + 5400)
        for bad in ("", "P", "PT", "1h", "PT1S", "P1W", "PT-1H", "pt1h", "P1DT", "PT\u0661H", "PT1H "):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rules.duration_seconds(bad)


class CheckTests(unittest.TestCase):
    def assertProblem(self, text, expected, **where):
        _, problems = check(text, **where)
        self.assertTrue(any(expected in problem for problem in problems), f"{expected!r} not in {problems}")

    def test_each_mistake_is_reported(self):
        cases = (
            (changed("Severity: Medium", "Severity: Critical"), "Severity 'Critical'"),
            (changed("Tactics: CredentialAccess", "Tactics: Credential Access"), "not a tactic"),
            (changed("Tactics: CredentialAccess", "Tactics: Impact"), "T1110 belongs to CredentialAccess"),
            (changed("Techniques: T1110", "Techniques: T9999"), "not in the technique table"),
            (changed("Sub-techniques: T1110.003", "Sub-techniques: T1078.004"), "its technique must be listed"),
            (changed("Frequency: PT1H", "Frequency: PT2H"), "Period must be at least as long"),
            (changed("Frequency: PT1H", "Frequency: PT1M"), "outside 5 minutes to 14 days"),
            (changed("Period: PT1H", "Period: P15D"), "outside 5 minutes to 14 days"),
            (changed("Period: PT1H", "Period: 1h"), "not a duration"),
            (changed("ago(1h)", "ago(7d)"), "looks back further"),
            (changed("Entities: IP(Address=IPAddress)", "Entities: IP(Addr=IPAddress)"), "no identifier 'Addr'"),
            (changed("Entities: IP(Address=IPAddress)", "Entities: Server(Name=IPAddress)"), "not a supported entity type"),
            (changed("Entities: IP(Address=IPAddress)", "Entities: IP(Address=SourceAddress)"), "SourceAddress is mapped but never appears"),
            (changed("Custom details: Attempts", "Custom details: Attempts, Attempts"), "lists a key twice"),
            (changed("Custom details: Attempts", "Custom details: Bad-Key=Attempts"), "letters and digits"),
            (changed("Tables: SigninLogs", "Tables: SigninLogs, AuditLogs"), "Tables says"),
            (changed("ResultType ==", "ResultTyp =="), "unknown name ResultTyp"),
            (changed("Title: Many failed sign-ins from one address", "Title: Many failed sign-ins."), "full stop"),
            (changed("References: https://learn.microsoft.com/entra/", "References: http://example.com"), "not an https link"),
            (changed("// Tuning: Raise the threshold for large offices behind one address.", "// Tuning: none"), "Tuning is too short"),
            (changed("// Entities: IP(Address=IPAddress)\n", ""), "needs at least one entity mapping"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: CustomDetails(Missing), P1D"), "custom detail Missing"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: Entities(Account), PT5H"), "entity Account"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: AllEntities, P30D"), "5 minutes to 7 days"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Alerts: OnePerDay"), "Alerts 'OnePerDay'"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Trigger: Above 0"), "Trigger operator"),
            (changed("| where Attempts > 20", "| where Attempts > {Threshold}"), "placeholder"),
            (changed("Entities: IP(Address=IPAddress)", "Entities: IP(Address=IPAddress, Address=IPAddress)"), "uses an identifier twice"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: Entities(), PT5H"), "must name at least one thing"),
            (changed("// Period: PT1H", "// Period: PT1H\n// Incidents: CustomDetails(), PT5H"), "must name at least one thing"),
            (changed("ago(1h)", "ago(Window)"), "cannot tell how far ago(...) looks back"),
            (changed("| where TimeGenerated > ago(1h)", "| where TimeGenerated > now(-7d)"), "now() with an offset"),
            (changed("| where ResultType ==", "\n| where ResultType =="), "has an empty line"),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                self.assertProblem(text, expected)

    def test_a_let_name_used_as_lookback_is_measured(self):
        text = changed("SigninLogs\n| where TimeGenerated > ago(1h)", "let Window = 7d;\nSigninLogs\n| where TimeGenerated > ago(Window)")
        self.assertProblem(text, "looks back further")

    def test_problems_in_the_query_give_the_line_of_the_file(self):
        header_lines = VALID[: VALID.index("\nSigninLogs\n") + 1].count("\n")
        _, problems = check(changed("ResultType ==", "ResultTyp =="))
        self.assertTrue(any(p.startswith(f"line {header_lines + 3}: unknown name ResultTyp") for p in problems), problems)
        _, problems = check(changed('ResultType == "50126"', 'ResultType == "50126'))
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith(f"line {header_lines + 3}: unexpected character"), problems)
        _, problems = check(changed("ago(1h)", "ago(Window)"))
        self.assertTrue(any(p.startswith(f"line {header_lines + 2}: cannot tell") for p in problems), problems)

    def test_files_with_a_byte_order_mark_or_other_line_endings(self):
        for text in ("\ufeff" + VALID, VALID.replace("\n", "\r\n"), VALID.replace("\n", "\r")):
            with self.subTest(start=repr(text[:12])):
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / "identity-sign-ins" / "ID-900-test.kql"
                    path.parent.mkdir()
                    path.write_bytes(text.encode("utf-8"))
                    rule = rules.parse_rule(path)
                    self.assertEqual(rules.check_rule(rule, SCHEMA), [])
                    self.assertNotIn("\r", rule.query)

    def test_a_file_that_is_not_utf8_names_the_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity-sign-ins" / "ID-900-test.kql"
            path.parent.mkdir()
            path.write_bytes(VALID.encode("utf-8").replace(b"address", b"addre\xff\xfe", 1))
            with self.assertRaises(rules.RuleError) as raised:
                rules.parse_rule(path)
            self.assertIn("ID-900-test.kql", str(raised.exception))
            self.assertIn("not UTF-8", str(raised.exception))

    def test_ten_entity_mappings_are_allowed_and_eleven_are_not(self):
        ten = "; ".join(["IP(Address=IPAddress)"] * 10)
        _, problems = check(changed("Entities: IP(Address=IPAddress)", f"Entities: {ten}"))
        self.assertEqual(problems, [])
        _, problems = check(changed("Entities: IP(Address=IPAddress)", f"Entities: {ten}; IP(Address=IPAddress)"))
        self.assertTrue(any("at most 10 entity mappings" in p for p in problems))

    def test_a_long_lookback_needs_an_hourly_schedule(self):
        text = changed("Frequency: PT1H", "Frequency: PT15M").replace("Period: PT1H", "Period: P7D")
        self.assertProblem(text, "no more often than hourly")

    def test_file_name_and_folder_must_match_the_id(self):
        self.assertProblem(VALID, "file name must start with ID-900-", name="spray.kql")
        self.assertProblem(VALID, "must look like PA-001", area="privileged-access")
        _, problems = check(VALID, area="somewhere-else")
        self.assertIn("is not one of the areas", problems[0])

    def test_a_file_without_a_query(self):
        header = VALID.split("SigninLogs\n|")[0]
        self.assertProblem(header, "no query below the header")

    def test_incident_grouping_options(self):
        rule, problems = check(changed("// Period: PT1H", "// Period: PT1H\n// Incidents: none"))
        self.assertEqual(problems, [])
        configuration = rules.rule_properties(rule, False)["incidentConfiguration"]
        self.assertIs(configuration["createIncident"], False)
        self.assertIs(configuration["groupingConfiguration"]["enabled"], False)
        rule, problems = check(changed("// Period: PT1H", "// Period: PT1H\n// Incidents: Entities(IP), PT12H"))
        self.assertEqual(problems, [])
        grouping = rules.rule_properties(rule, False)["incidentConfiguration"]["groupingConfiguration"]
        self.assertEqual((grouping["matchingMethod"], grouping["groupByEntities"], grouping["lookbackDuration"]),
                         ("Selected", ["IP"], "PT12H"))  # fmt: skip

    def test_duplicate_ids_and_titles_across_rules(self):
        loaded = rules.load_rules()
        problems = rules.check_rules([loaded[0], loaded[0]], SCHEMA)
        self.assertTrue(any("Id 'ID-001' is used by more than one rule" in p for p in problems))
        self.assertTrue(any(p.startswith("Title ") for p in problems))


if __name__ == "__main__":
    unittest.main()
