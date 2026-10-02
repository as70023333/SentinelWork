"""Read the detection rule sources and turn them into Sentinel scheduled analytics rules.

A rule is one ``.kql`` file: a comment header with the rule settings, then the query. The header
is the single place a rule is described, so the deployable template, the rule catalogue and the
workbook that shows the rule's alerts can never disagree with each other.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import kql

CONTENT_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = CONTENT_ROOT / "Detection-rules"

# The seven areas, in the order they are listed everywhere. Each area has one workbook.
AREAS: dict[str, dict[str, str]] = {
    "identity-sign-ins": {"prefix": "ID", "title": "Identity sign-ins"},
    "privileged-access": {"prefix": "PA", "title": "Privileged access changes"},
    "endpoint-threats": {"prefix": "EP", "title": "Endpoint threats"},
    "email-phishing": {"prefix": "EM", "title": "Email and phishing"},
    "azure-activity": {"prefix": "AZ", "title": "Azure activity"},
    "insider-risk-exfiltration": {"prefix": "EX", "title": "Insider risk and data exfiltration"},
    "soc-operations": {"prefix": "SO", "title": "SOC operations"},
}

# Values the Sentinel alert rules API accepts (api-version 2024-03-01).
API_VERSION = "2024-03-01"
SEVERITIES = ("High", "Medium", "Low", "Informational")
TRIGGER_OPERATORS = ("GreaterThan", "LessThan", "Equal", "NotEqual")
EVENT_GROUPING = ("AlertPerResult", "SingleAlert")
TACTICS = (
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "Exfiltration", "CommandAndControl", "Impact",
)  # fmt: skip

# Entity types and the identifiers each one accepts in an entity mapping
# (https://learn.microsoft.com/azure/sentinel/entities-reference).
ENTITY_IDENTIFIERS: dict[str, tuple[str, ...]] = {
    "Account": ("Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid", "AadTenantId", "AadUserId",
                "PUID", "IsDomainJoined", "DisplayName", "ObjectGuid"),
    "Host": ("DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName", "AzureID", "OMSAgentID",
             "OSFamily", "OSVersion", "IsDomainJoined"),
    "IP": ("Address",),
    "URL": ("Url",),
    "AzureResource": ("ResourceId",),
    "CloudApplication": ("AppId", "Name", "InstanceName"),
    "DNS": ("DomainName",),
    "File": ("Directory", "Name"),
    "FileHash": ("Algorithm", "Value"),
    "Process": ("ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"),
    "RegistryKey": ("Hive", "Key"),
    "RegistryValue": ("Name", "Value", "ValueType"),
    "Mailbox": ("MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId", "RiskLevel"),
    "MailMessage": ("Recipient", "Urls", "Threats", "Sender", "SenderIP", "ReceivedDate", "NetworkMessageId",
                    "InternetMessageId", "Subject", "AntispamDirection", "DeliveryAction", "DeliveryLocation"),
}  # fmt: skip

# MITRE ATT&CK techniques used by the rules and the tactics each belongs to. Sentinel shows a
# technique under a tactic, so a rule may only list a technique next to one of its own tactics.
TECHNIQUE_TACTICS: dict[str, tuple[str, ...]] = {
    "T1003": ("CredentialAccess",),
    "T1027": ("DefenseEvasion",),
    "T1041": ("Exfiltration",),
    "T1048": ("Exfiltration",),
    "T1052": ("Exfiltration",),
    "T1059": ("Execution",),
    "T1078": ("DefenseEvasion", "Persistence", "PrivilegeEscalation", "InitialAccess"),
    "T1098": ("Persistence", "PrivilegeEscalation"),
    "T1105": ("CommandAndControl",),
    "T1110": ("CredentialAccess",),
    "T1114": ("Collection",),
    "T1204": ("Execution",),
    "T1213": ("Collection",),
    "T1485": ("Impact",),
    "T1490": ("Impact",),
    "T1528": ("CredentialAccess",),
    "T1530": ("Collection",),
    "T1556": ("CredentialAccess", "DefenseEvasion", "Persistence"),
    "T1562": ("DefenseEvasion",),
    "T1564": ("DefenseEvasion",),
    "T1566": ("InitialAccess",),
    "T1567": ("Exfiltration",),
    "T1621": ("CredentialAccess",),
    "T1651": ("Execution",),
}

# Limits Sentinel places on a scheduled rule.
MAX_NAME = 256
MAX_DESCRIPTION = 5000
MAX_QUERY = 10000
MAX_ENTITY_MAPPINGS = 10
MAX_IDENTIFIERS = 3
MAX_CUSTOM_DETAILS = 20
MIN_SECONDS = 5 * 60
MAX_SECONDS = 14 * 86400

HEADER_KEYS = (
    "Title", "Id", "Severity", "Tactics", "Techniques", "Sub-techniques", "Tables", "Frequency", "Period",
    "Trigger", "Alerts", "Incidents", "Entities", "Custom details", "Description", "False positives",
    "Tuning", "Response", "References",
)  # fmt: skip
REQUIRED_KEYS = (
    "Title", "Id", "Severity", "Tables", "Frequency", "Period", "Description", "False positives", "Tuning",
    "Response",
)  # fmt: skip

_ID_SPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/as70023333/SentinelWork")
_DURATION = re.compile(r"^P(?:([0-9]+)D)?(?:T(?=[0-9])(?:([0-9]+)H)?(?:([0-9]+)M)?)?$")
_HEADER_LINE = re.compile(r"^// ([A-Z][A-Za-z\- ]*?): ?(.*)$")
_CONTINUATION = re.compile(r"^//\s{3,}(\S.*)$")
_ENTITY = re.compile(r"^([A-Za-z]+)\(([^()]*)\)$")
_COLUMN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RuleError(ValueError):
    """A rule file is not valid. The message names the file."""


@dataclass(frozen=True)
class Rule:
    path: Path
    area: str
    id: str
    title: str
    severity: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    sub_techniques: tuple[str, ...]
    tables: tuple[str, ...]
    frequency: str
    period: str
    trigger_operator: str
    trigger_threshold: int
    alerts: str
    incidents: dict
    entities: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    custom_details: tuple[tuple[str, str], ...]
    description: str
    false_positives: str
    tuning: str
    response: str
    references: tuple[str, ...]
    query: str
    query_line: int = 1  # the line of the file the query starts on

    @property
    def guid(self) -> str:
        """The rule's resource name in Sentinel. Fixed, so deploying again updates the rule."""
        return str(uuid.uuid5(_ID_SPACE, f"rule/{self.id}"))

    @property
    def output_columns(self) -> list[str]:
        """Columns the query result must contain for the entity mappings and custom details."""
        columns: list[str] = []
        for _, pairs in self.entities:
            columns.extend(column for _, column in pairs)
        columns.extend(column for _, column in self.custom_details)
        return list(dict.fromkeys(columns))


def duration_seconds(text: str) -> int:
    """Seconds in an ISO 8601 duration such as PT1H or P1D. Raises ValueError when it is not one."""
    match = _DURATION.match(text)
    if match is None or not any(match.groups()):
        raise ValueError(f"{text!r} is not a duration like PT30M, PT1H or P1D")
    days, hours, minutes = (int(part or 0) for part in match.groups())
    return days * 86400 + hours * 3600 + minutes * 60


def split_header(text: str, name: str) -> tuple[dict[str, str], str, int]:
    """Split a rule file into its header fields, the query below them, and the query's first line."""
    fields: dict[str, str] = {}
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    current = ""
    index = 0
    for index, line in enumerate(lines):
        if not line.startswith("//"):
            break
        continued = _CONTINUATION.match(line)
        if continued and current:
            fields[current] = f"{fields[current]} {continued.group(1).strip()}".strip()
            continue
        match = _HEADER_LINE.match(line)
        if match is None:
            raise RuleError(f"{name}: line {index + 1} is not 'Key: value' or an indented continuation")
        current = match.group(1)
        if current not in HEADER_KEYS:
            raise RuleError(f"{name}: unknown header field {current!r}")
        if current in fields:
            raise RuleError(f"{name}: header field {current!r} appears twice")
        fields[current] = match.group(2).strip()
    else:
        index = len(lines)
    while index < len(lines) and not lines[index].strip():
        index += 1
    query = "\n".join(lines[index:]).rstrip()
    return fields, query, index + 1


def _list(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _parse_entities(value: str, name: str) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    entities = []
    for part in (p.strip() for p in value.split(";")):
        if not part:
            continue
        match = _ENTITY.match(part)
        if match is None:
            raise RuleError(f"{name}: entity {part!r} is not written as Type(Identifier=Column, ...)")
        pairs = []
        for pair in _list(match.group(2)):
            identifier, _, column = (piece.strip() for piece in pair.partition("="))
            if not identifier or not column:
                raise RuleError(f"{name}: entity {part!r} needs Identifier=Column pairs")
            pairs.append((identifier, column))
        entities.append((match.group(1), tuple(pairs)))
    return tuple(entities)


def _parse_custom_details(value: str, name: str) -> tuple[tuple[str, str], ...]:
    details = []
    for part in _list(value):
        key, _, column = (piece.strip() for piece in part.partition("="))
        column = column or key
        if not key:
            raise RuleError(f"{name}: empty custom detail")
        details.append((key, column))
    return tuple(details)


def _parse_incidents(value: str, name: str) -> dict:
    """'AllEntities, PT5H', 'CustomDetails(DataType), P1D', 'Entities(Account, IP), PT5H' or 'none'."""
    text = value.strip() or "AllEntities, PT5H"
    if text.lower() == "none":
        return {"create": False, "method": "AllEntities", "lookback": "PT5H", "entities": (), "details": ()}
    how, _, lookback = text.rpartition(",")
    how, lookback = how.strip(), lookback.strip()
    if not how:
        raise RuleError(f"{name}: Incidents must be '<grouping>, <lookback>' or 'none'")
    if how == "AllEntities":
        return {"create": True, "method": "AllEntities", "lookback": lookback, "entities": (), "details": ()}
    match = _ENTITY.match(how)
    if match and match.group(1) == "CustomDetails":
        return {"create": True, "method": "Selected", "lookback": lookback, "entities": (),
                "details": _list(match.group(2))}  # fmt: skip
    if match and match.group(1) == "Entities":
        return {"create": True, "method": "Selected", "lookback": lookback, "entities": _list(match.group(2)),
                "details": ()}  # fmt: skip
    raise RuleError(f"{name}: Incidents grouping {how!r} is not AllEntities, Entities(...) or CustomDetails(...)")


def parse_rule(path: Path) -> Rule:
    """Read one rule file. Raises RuleError when the header cannot be read at all."""
    name = f"{path.parent.name}/{path.name}"
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as error:
        raise RuleError(f"{name}: the file is not UTF-8 text ({error.reason} at byte {error.start})") from error
    fields, query, query_line = split_header(text, name)
    missing = [key for key in REQUIRED_KEYS if not fields.get(key)]
    if missing:
        raise RuleError(f"{name}: missing header field(s): {', '.join(missing)}")
    trigger = fields.get("Trigger", "GreaterThan 0").split()
    if len(trigger) != 2 or not re.fullmatch(r"[0-9]{1,5}", trigger[1]):
        raise RuleError(f"{name}: Trigger must look like 'GreaterThan 0'")
    return Rule(
        path=path,
        area=path.parent.name,
        id=fields["Id"],
        title=fields["Title"],
        severity=fields["Severity"],
        tactics=_list(fields.get("Tactics", "")),
        techniques=_list(fields.get("Techniques", "")),
        sub_techniques=_list(fields.get("Sub-techniques", "")),
        tables=_list(fields["Tables"]),
        frequency=fields["Frequency"],
        period=fields["Period"],
        trigger_operator=trigger[0],
        trigger_threshold=int(trigger[1]),
        alerts=fields.get("Alerts", "AlertPerResult"),
        incidents=_parse_incidents(fields.get("Incidents", ""), name),
        entities=_parse_entities(fields.get("Entities", ""), name),
        custom_details=_parse_custom_details(fields.get("Custom details", ""), name),
        description=fields["Description"],
        false_positives=fields["False positives"],
        tuning=fields["Tuning"],
        response=fields["Response"],
        references=tuple(fields.get("References", "").split()),
        query=query,
        query_line=query_line,
    )


def check_rule(rule: Rule, schema: dict[str, dict[str, str]]) -> list[str]:
    """Return everything wrong with one rule. An empty list means it is ready to deploy."""
    problems: list[str] = []
    area = AREAS.get(rule.area)
    if area is None:
        return [f"folder {rule.area!r} is not one of the areas: {', '.join(AREAS)}"]
    if not re.fullmatch(rf"{area['prefix']}-\d{{3}}", rule.id):
        problems.append(f"Id {rule.id!r} must look like {area['prefix']}-001 for this folder")
    if not rule.path.name.startswith(f"{rule.id}-") or rule.path.suffix != ".kql":
        problems.append(f"the file name must start with {rule.id}- and end with .kql")
    if not rule.title or len(rule.title) > MAX_NAME:
        problems.append(f"Title must be 1 to {MAX_NAME} characters")
    if rule.title != rule.title.strip() or rule.title.endswith("."):
        problems.append("Title must not end with a full stop or spaces")
    if rule.severity not in SEVERITIES:
        problems.append(f"Severity {rule.severity!r} is not one of {', '.join(SEVERITIES)}")
    for tactic in rule.tactics:
        if tactic not in TACTICS:
            problems.append(f"Tactics: {tactic!r} is not a tactic Sentinel accepts")
    if len(set(rule.tactics)) != len(rule.tactics):
        problems.append("Tactics lists a value twice")
    for technique in rule.techniques:
        allowed = TECHNIQUE_TACTICS.get(technique)
        if allowed is None:
            problems.append(f"Techniques: {technique!r} is not in the technique table in rules.py")
        elif not set(allowed) & set(rule.tactics):
            problems.append(f"Techniques: {technique} belongs to {', '.join(allowed)}; list one of them in Tactics")
    for sub in rule.sub_techniques:
        if not re.fullmatch(r"T\d{4}\.\d{3}", sub) or sub.split(".")[0] not in rule.techniques:
            problems.append(f"Sub-techniques: {sub!r} must look like T1110.003 and its technique must be listed")

    seconds = {}
    for label, value in (("Frequency", rule.frequency), ("Period", rule.period)):
        try:
            seconds[label] = duration_seconds(value)
        except ValueError as error:
            problems.append(f"{label}: {error}")
            continue
        if not MIN_SECONDS <= seconds[label] <= MAX_SECONDS:
            problems.append(f"{label}: {value} is outside 5 minutes to 14 days")
    if len(seconds) == 2:
        if seconds["Period"] < seconds["Frequency"]:
            problems.append("Period must be at least as long as Frequency, or events between runs are never read")
        if seconds["Period"] > 2 * 86400 and seconds["Frequency"] < 3600:
            problems.append("a rule that reads more than 2 days must run no more often than hourly")
        try:
            longest, unclear = kql.lookback(rule.query)
        except kql.KqlError:
            longest, unclear = 0.0, []  # reported with its line further down
        problems.extend(_file_line(problem, rule) for problem in unclear)
        if longest > seconds["Period"]:
            problems.append(f"the query looks back further (ago) than Period {rule.period}; Sentinel only reads the Period")
        problems.extend(_arrival_problems(rule, seconds["Frequency"]))
    if rule.trigger_operator not in TRIGGER_OPERATORS:
        problems.append(f"Trigger operator {rule.trigger_operator!r} is not one of {', '.join(TRIGGER_OPERATORS)}")
    if not 0 <= rule.trigger_threshold <= 10000:
        problems.append("Trigger threshold must be 0 to 10000")
    if rule.alerts not in EVENT_GROUPING:
        problems.append(f"Alerts {rule.alerts!r} is not one of {', '.join(EVENT_GROUPING)}")

    if len(rule.entities) > MAX_ENTITY_MAPPINGS:
        problems.append(f"at most {MAX_ENTITY_MAPPINGS} entity mappings")
    for entity_type, pairs in rule.entities:
        identifiers = ENTITY_IDENTIFIERS.get(entity_type)
        if identifiers is None:
            problems.append(f"Entities: {entity_type!r} is not a supported entity type")
            continue
        if not 1 <= len(pairs) <= MAX_IDENTIFIERS:
            problems.append(f"Entities: {entity_type} needs 1 to {MAX_IDENTIFIERS} identifiers")
        if len({identifier for identifier, _ in pairs}) != len(pairs):
            problems.append(f"Entities: {entity_type} uses an identifier twice")
        for identifier, column in pairs:
            if identifier not in identifiers:
                problems.append(f"Entities: {entity_type} has no identifier {identifier!r}")
            if not _COLUMN.match(column):
                problems.append(f"Entities: {column!r} is not a column name")
    if len(rule.custom_details) > MAX_CUSTOM_DETAILS:
        problems.append(f"at most {MAX_CUSTOM_DETAILS} custom details")
    keys = [key for key, _ in rule.custom_details]
    if len(set(keys)) != len(keys):
        problems.append("Custom details lists a key twice")
    for key, column in rule.custom_details:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) or not _COLUMN.match(column):
            problems.append(f"Custom details: {key}={column} must be letters and digits")

    incidents = rule.incidents
    try:
        lookback = duration_seconds(incidents["lookback"])
        if not MIN_SECONDS <= lookback <= 7 * 86400:
            problems.append("Incidents: the grouping lookback must be 5 minutes to 7 days")
    except ValueError as error:
        problems.append(f"Incidents: {error}")
    entity_types = {entity_type for entity_type, _ in rule.entities}
    for entity_type in incidents["entities"]:
        if entity_type not in entity_types:
            problems.append(f"Incidents: groups by entity {entity_type}, which the rule does not map")
    for key in incidents["details"]:
        if key not in keys:
            problems.append(f"Incidents: groups by custom detail {key}, which the rule does not define")
    if incidents["create"] and incidents["method"] == "AllEntities" and not rule.entities:
        problems.append("Incidents: grouping by all entities needs at least one entity mapping")
    if incidents["method"] == "Selected" and not incidents["entities"] and not incidents["details"]:
        problems.append("Incidents: Entities(...) or CustomDetails(...) must name at least one thing to group by")

    for label, value in (("Description", rule.description), ("False positives", rule.false_positives),
                         ("Tuning", rule.tuning), ("Response", rule.response)):  # fmt: skip
        if len(value) < 20:
            problems.append(f"{label} is too short to be useful")
    if len(rule_description(rule)) > MAX_DESCRIPTION:
        problems.append(f"the description text is longer than {MAX_DESCRIPTION} characters")
    for reference in rule.references:
        if not reference.startswith("https://"):
            problems.append(f"References: {reference!r} is not an https link")

    if not rule.query:
        return problems + ["the file has no query below the header"]
    try:
        tokens = kql.tokenize(rule.query)
        body = kql.strip_comments(rule.query)
    except kql.KqlError as error:
        return problems + [_file_line(str(error), rule)]
    if not 1 <= len(body) <= MAX_QUERY:
        problems.append(f"the query must be 1 to {MAX_QUERY} characters")
    if "\n\n" in body:
        problems.append("the query has an empty line; the Logs editor would run only the part above it")
    problems.extend(kql.check_names(rule.query, schema, first_line=rule.query_line))
    if kql.has_placeholder(rule.query):
        problems.append("a rule query must not contain a workbook placeholder such as {TimeRange}")
    used = kql.tables_used(tokens, schema)
    if sorted(used) != sorted(rule.tables):
        problems.append(f"Tables says {', '.join(rule.tables)} but the query reads {', '.join(used) or 'nothing'}")
    names = {token.text for token in tokens if token.kind == "name"}
    for column in rule.output_columns:
        if column not in names:
            problems.append(f"column {column} is mapped but never appears in the query")
    return problems


# Sentinel starts a scheduled rule five minutes after the time it is scheduled for.
RUN_DELAY_SECONDS = 300


def _arrival_problems(rule: Rule, frequency: int) -> list[str]:
    """Check that rows selected by arrival time are selected once: no gap and no overlap between runs."""
    try:
        windows, earlier, problems = kql.arrival_windows(rule.query)
    except kql.KqlError:
        return []  # reported with its line elsewhere
    for lower, upper in windows:
        if upper != RUN_DELAY_SECONDS:
            problems.append("an arrival window must end at ago(5m): Sentinel runs a rule five minutes late, and "
                            "rows that arrive in that time belong to the next run")  # fmt: skip
        if lower - upper != frequency:
            problems.append(f"an arrival window must be exactly as long as Frequency {rule.frequency}, or rows "
                            "are read twice or never")  # fmt: skip
    for bound in earlier:
        if bound not in {lower for lower, _ in windows}:
            problems.append("'ingestion_time() <= ago(X)' must use the start of the arrival window, so the two "
                            "parts do not overlap or leave a gap")  # fmt: skip
    return problems


def _file_line(problem: str, rule: Rule) -> str:
    """Rewrite every 'line N' counted within the query as the line of the rule file."""
    return re.sub(r"\bline (\d+)", lambda match: f"line {int(match.group(1)) + rule.query_line - 1}", problem)


def stray_rule_files(rules_dir: Path | None = None) -> list[str]:
    """Rule files the build would silently ignore: wrong folder depth or an upper-case extension."""
    root = rules_dir or RULES_DIR
    loaded = set(root.glob("*/*.kql"))
    return [
        f"{path.relative_to(root).as_posix()}: rule files must be Detection-rules/<area>/<name>.kql"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.suffix.lower() == ".kql" and path not in loaded
    ]


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Every rule under the rules folder, ordered by area then id."""
    root = rules_dir or RULES_DIR
    rules = [parse_rule(path) for path in sorted(root.glob("*/*.kql"))]
    order = {area: index for index, area in enumerate(AREAS)}
    return sorted(rules, key=lambda rule: (order.get(rule.area, len(order)), rule.id))


def check_rules(rules: list[Rule], schema: dict[str, dict[str, str]]) -> list[str]:
    """Problems across all rules, each prefixed with the rule file."""
    problems: list[str] = []
    for rule in rules:
        problems.extend(f"{rule.area}/{rule.path.name}: {problem}" for problem in check_rule(rule, schema))
    for label, values in (("Id", [rule.id for rule in rules]), ("Title", [rule.title.lower() for rule in rules])):
        for value in sorted({value for value in values if values.count(value) > 1}):
            problems.append(f"{label} {value!r} is used by more than one rule")
    return problems


def rule_description(rule: Rule) -> str:
    """The text shown on the rule in Sentinel: what it finds, what else can trigger it, what to do."""
    parts = [
        rule.description,
        f"False positives: {rule.false_positives}",
        f"Response: {rule.response}",
        f"Source: SentinelWork rule {rule.id}.",
    ]
    if rule.sub_techniques:
        parts.insert(3, f"MITRE ATT&CK sub-techniques: {', '.join(rule.sub_techniques)}.")
    return "\n\n".join(parts)


def rule_properties(rule: Rule, enabled: bool) -> dict:
    """The 'properties' object of a scheduled alert rule, as the Sentinel API defines it."""
    incidents = rule.incidents
    properties: dict = {
        "displayName": rule.title,
        "description": rule_description(rule),
        "severity": rule.severity,
        "enabled": enabled,
        "query": kql.strip_comments(rule.query),
        "queryFrequency": rule.frequency,
        "queryPeriod": rule.period,
        "triggerOperator": rule.trigger_operator,
        "triggerThreshold": rule.trigger_threshold,
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": list(rule.tactics),
        "techniques": list(rule.techniques),
        "eventGroupingSettings": {"aggregationKind": rule.alerts},
        "incidentConfiguration": {
            "createIncident": incidents["create"],
            "groupingConfiguration": {
                "enabled": incidents["create"],
                "reopenClosedIncident": False,
                "lookbackDuration": incidents["lookback"],
                "matchingMethod": incidents["method"],
                "groupByEntities": list(incidents["entities"]),
                "groupByAlertDetails": [],
                "groupByCustomDetails": list(incidents["details"]),
            },
        },
    }
    if rule.entities:
        properties["entityMappings"] = [
            {
                "entityType": entity_type,
                "fieldMappings": [{"identifier": identifier, "columnName": column} for identifier, column in pairs],
            }
            for entity_type, pairs in rule.entities
        ]
    if rule.custom_details:
        properties["customDetails"] = dict(rule.custom_details)
    return properties
