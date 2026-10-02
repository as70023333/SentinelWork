"""Read the workbook sources and turn them into Azure Workbook gallery JSON.

A workbook is one ``.toml`` file: a title, an introduction and a list of tabs, each with the
tiles, charts and tables it shows and the KQL behind them. Every workbook also gets a
"Detections" tab that is generated from the detection rules of the same area, so the tab always
lists exactly the rules that exist.
"""

from __future__ import annotations

import json
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import kql
from .rules import AREAS, CONTENT_ROOT, Rule

WORKBOOKS_DIR = CONTENT_ROOT / "Workbooks"
SOURCES_DIR = WORKBOOKS_DIR / "src"

WORKBOOK_SCHEMA = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
LOGS = {"queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces"}
TIME_PARAMETER = "TimeRange"
TAB_PARAMETER = "Tab"
DETECTIONS_TAB = "Detections"
# Tables the generated Detections tab reads. Every Sentinel workspace has them.
DETECTION_TABLES = ("SecurityAlert", "SecurityIncident")

CHARTS = ("timechart", "areachart", "barchart", "piechart")
KINDS = ("text", "tiles", "table", *CHARTS)
RANGES_MS = {
    "1h": 3600000, "4h": 14400000, "12h": 43200000, "1d": 86400000, "2d": 172800000, "3d": 259200000,
    "7d": 604800000, "14d": 1209600000, "30d": 2592000000, "60d": 5184000000, "90d": 7776000000,
}  # fmt: skip
SEVERITY_COLOURS = (("High", "redBright"), ("Medium", "orange"), ("Low", "yellow"), ("Informational", "gray"))
PALETTES = ("blue", "green", "orange", "purple", "turquoise", "redBright", "yellow", "gray", "coldHot", "greenRed",
            "redGreen")  # fmt: skip

_ID_SPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/as70023333/SentinelWork")

ITEM_KEYS = {
    "text": {"kind", "text", "width"},
    "tiles": {"kind", "title", "query", "width", "label", "value", "note", "empty"},
    "table": {"kind", "title", "query", "width", "bars", "heat", "severity", "link", "link_label", "hide", "empty",
              "palette", "rows"},
}  # fmt: skip
for _chart in CHARTS:
    ITEM_KEYS[_chart] = {"kind", "title", "query", "width", "empty", "colours"}


class WorkbookError(ValueError):
    """A workbook source file is not valid. The message names the file."""


@dataclass(frozen=True)
class Item:
    kind: str
    settings: dict

    @property
    def query(self) -> str:
        return self.settings.get("query", "").strip("\n")


@dataclass(frozen=True)
class Tab:
    name: str
    items: tuple[Item, ...]


@dataclass(frozen=True)
class Workbook:
    path: Path
    key: str
    name: str
    file: str
    area: str
    summary: str
    intro: str
    tables: tuple[str, ...]
    optional_tables: tuple[str, ...]
    default_range: str
    tabs: tuple[Tab, ...]

    @property
    def guid_seed(self) -> str:
        return f"workbook/{self.key}"


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_ID_SPACE, "/".join(parts)))


def parse_workbook(path: Path) -> Workbook:
    """Read one workbook source. Raises WorkbookError when the file cannot be understood."""
    name = path.name
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise WorkbookError(f"{name}: not valid TOML: {error}") from error
    allowed = {"name", "file", "area", "summary", "intro", "tables", "optional_tables", "default_range", "tab"}
    unknown = set(data) - allowed
    if unknown:
        raise WorkbookError(f"{name}: unknown setting(s): {', '.join(sorted(unknown))}")
    for key in ("name", "file", "area", "summary", "intro", "tables", "tab"):
        if not data.get(key):
            raise WorkbookError(f"{name}: missing {key!r}")
    tabs = []
    for tab in data["tab"]:
        if not isinstance(tab, dict) or not tab.get("name") or not tab.get("item"):
            raise WorkbookError(f"{name}: every [[tab]] needs a name and at least one [[tab.item]]")
        items = []
        for raw in tab["item"]:
            kind = raw.get("kind", "")
            if kind not in KINDS:
                raise WorkbookError(f"{name}: tab {tab['name']!r}: kind {kind!r} is not one of {', '.join(KINDS)}")
            extra = set(raw) - ITEM_KEYS[kind]
            if extra:
                raise WorkbookError(f"{name}: tab {tab['name']!r}: a {kind} item cannot have {', '.join(sorted(extra))}")
            items.append(Item(kind, dict(raw)))
        tabs.append(Tab(str(tab["name"]), tuple(items)))
    return Workbook(
        path=path,
        key=path.stem,
        name=str(data["name"]),
        file=str(data["file"]),
        area=str(data["area"]),
        summary=str(data["summary"]),
        intro=str(data["intro"]).strip(),
        tables=tuple(data["tables"]),
        optional_tables=tuple(data.get("optional_tables", ())),
        default_range=str(data.get("default_range", "7d")),
        tabs=tuple(tabs),
    )


def load_workbooks(sources_dir: Path | None = None) -> list[Workbook]:
    """Every workbook source, in the order of the areas."""
    books = [parse_workbook(path) for path in sorted((sources_dir or SOURCES_DIR).glob("*.toml"))]
    order = {area: index for index, area in enumerate(AREAS)}
    return sorted(books, key=lambda book: (order.get(book.area, len(order)), book.key))


# ---------------------------------------------------------------------------------------------
# The generated Detections tab


def kql_string(text: str) -> str:
    """A KQL string literal for the text."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rule_names(rules: list[Rule]) -> str:
    return "let RuleNames = dynamic([" + ", ".join(kql_string(rule.title) for rule in rules) + "]);"


def detection_items(rules: list[Rule]) -> tuple[Item, ...]:
    """The items of the Detections tab for the rules of one area."""
    rows = ",\n".join(
        "    " + ", ".join(kql_string(value) for value in (rule.id, rule.title, rule.severity, ", ".join(rule.tactics) or "Operational"))
        for rule in rules
    )
    names = _rule_names(rules)
    coverage = f"""let Rules = datatable(RuleId:string, AlertName:string, RuleSeverity:string, Tactics:string) [
{rows}
];
let AlertCounts = SecurityAlert
    | summarize arg_max(TimeGenerated, AlertName) by SystemAlertId
    | summarize AlertCount = count(), LastAlert = max(TimeGenerated) by AlertName;
Rules
| join kind=leftouter AlertCounts on AlertName
| project RuleId, Rule = AlertName, Severity = RuleSeverity, Tactics, Alerts = coalesce(AlertCount, 0), LastAlert
| order by RuleId asc"""
    over_time = f"""{names}
SecurityAlert
| where AlertName in (RuleNames)
| summarize arg_max(TimeGenerated, AlertName) by SystemAlertId
| summarize Alerts = count() by bin(TimeGenerated, {{TimeRange:grain}}), AlertName"""
    recent = f"""{names}
SecurityAlert
| where AlertName in (RuleNames)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project TimeGenerated, Rule = AlertName, Severity = AlertSeverity, Status,
          Details = tostring(parse_json(ExtendedProperties)["Custom Details"]), Entities
| order by TimeGenerated desc
| take 250"""
    incidents = f"""{names}
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title in (RuleNames)
| extend LabelText = tostring(Labels)
| project CreatedTime, IncidentNumber, Title, Severity, Status, Classification,
          AssignedTo = tostring(Owner.assignedTo),
          AgentDisposition = extract(@"soc-agent:(page|queue|auto_close|pending)", 1, LabelText), IncidentUrl
| order by CreatedTime desc
| take 250"""
    text = (
        "These are the detection rules in this repository for this area "
        "(`Detection-rules/` in SentinelWork). A rule with 0 alerts is either not deployed, "
        "not enabled, or has had nothing to report in the time range. Alerts are matched to "
        "rules by name, so a rule you rename in Sentinel stops being counted here."
    )
    return (
        Item("text", {"kind": "text", "text": text}),
        Item("table", {"kind": "table", "title": "Rule coverage", "query": coverage, "severity": "Severity",
                       "bars": ["Alerts"], "empty": "No rules are defined for this area."}),  # fmt: skip
        Item("barchart", {"kind": "barchart", "title": "Alerts over time, by rule", "query": over_time,
                          "empty": "None of these rules raised an alert in the time range."}),  # fmt: skip
        Item("table", {"kind": "table", "title": "Latest alerts", "query": recent, "severity": "Severity",
                       "width": 50, "empty": "None of these rules raised an alert in the time range."}),  # fmt: skip
        Item("table", {"kind": "table", "title": "Incidents created by these rules", "query": incidents,
                       "severity": "Severity", "link": "IncidentUrl", "link_label": "Open incident", "width": 50,
                       "empty": "No incidents from these rules in the time range."}),  # fmt: skip
    )


def all_tabs(book: Workbook, rules: list[Rule]) -> tuple[Tab, ...]:
    """The workbook's own tabs followed by the generated Detections tab."""
    own = [rule for rule in rules if rule.area == book.area]
    return (*book.tabs, Tab(DETECTIONS_TAB, detection_items(own)))


def workbook_queries(book: Workbook, rules: list[Rule]) -> list[tuple[str, str]]:
    """(label, query) for every query in the workbook, including the generated ones."""
    queries = []
    for tab in all_tabs(book, rules):
        for index, item in enumerate(tab.items, start=1):
            if item.kind != "text":
                queries.append((f"{tab.name} / {index}. {item.settings.get('title', item.kind)}", item.query))
    return queries


# ---------------------------------------------------------------------------------------------
# Checks


def check_workbook(book: Workbook, rules: list[Rule], schema: dict[str, dict[str, str]]) -> list[str]:
    """Return everything wrong with one workbook source."""
    problems: list[str] = []
    if book.area not in AREAS:
        problems.append(f"area {book.area!r} is not one of {', '.join(AREAS)}")
    if not book.file.isalnum():
        problems.append("file must be letters and digits only; .json is added for you")
    if book.default_range not in RANGES_MS:
        problems.append(f"default_range {book.default_range!r} is not one of {', '.join(RANGES_MS)}")
    for table in (*book.tables, *book.optional_tables):
        if table not in schema:
            problems.append(f"table {table!r} is not in the schema file")
    tab_names = [tab.name for tab in book.tabs]
    if len(set(tab_names)) != len(tab_names) or DETECTIONS_TAB in tab_names:
        problems.append(f"tab names must be unique and {DETECTIONS_TAB!r} is generated")

    read: set[str] = set()
    for tab in all_tabs(book, rules):
        for index, item in enumerate(tab.items, start=1):
            where = f"tab {tab.name!r} item {index}"
            settings = item.settings
            width = settings.get("width", 100)
            if not isinstance(width, int) or not 10 <= width <= 100:
                problems.append(f"{where}: width must be a whole number from 10 to 100")
            if item.kind == "text":
                if not str(settings.get("text", "")).strip():
                    problems.append(f"{where}: a text item needs text")
                continue
            if not settings.get("title"):
                problems.append(f"{where}: needs a title")
            if not item.query:
                problems.append(f"{where}: needs a query")
                continue
            problems.extend(f"{where}: query {problem}" for problem in kql.check_names(item.query, schema, workbook=True))
            try:
                filled = kql.fill_placeholders(item.query)
                tokens = kql.tokenize(filled)
            except kql.KqlError:
                continue
            read.update(kql.tables_used(tokens, schema))
            names = {token.text for token in tokens if token.kind == "name"}
            columns = []
            if item.kind == "tiles":
                for key in ("label", "value"):
                    if not settings.get(key):
                        problems.append(f"{where}: tiles need {key!r}")
                columns = [settings.get("label"), settings.get("value"), settings.get("note")]
            if item.kind == "table":
                columns = [*settings.get("bars", ()), *settings.get("heat", ()), *settings.get("hide", ()),
                           settings.get("severity"), settings.get("link")]  # fmt: skip
                if settings.get("palette", "blue") not in PALETTES:
                    problems.append(f"{where}: palette must be one of {', '.join(PALETTES)}")
            for column in columns:
                if column and column not in names:
                    problems.append(f"{where}: column {column!r} is formatted but never appears in the query")
            if item.kind in CHARTS and "render" in names:
                problems.append(f"{where}: leave out 'render'; the item kind chooses the chart")

    declared = set(book.tables) | set(book.optional_tables)
    undeclared = read - declared - set(DETECTION_TABLES)
    if undeclared:
        problems.append(f"queries read {', '.join(sorted(undeclared))} but tables/optional_tables do not list them")
    unused = declared - read
    if unused:
        problems.append(f"tables lists {', '.join(sorted(unused))} but no query reads them")
    return problems


def check_workbooks(books: list[Workbook], rules: list[Rule], schema: dict[str, dict[str, str]]) -> list[str]:
    problems: list[str] = []
    for book in books:
        problems.extend(f"{book.path.name}: {problem}" for problem in check_workbook(book, rules, schema))
    for label, values in (("file", [b.file.lower() for b in books]), ("name", [b.name.lower() for b in books]),
                          ("area", [b.area for b in books])):  # fmt: skip
        for value in sorted({value for value in values if values.count(value) > 1}):
            problems.append(f"workbook {label} {value!r} is used more than once")
    missing = [area for area in AREAS if area not in {book.area for book in books}]
    if books and missing:
        problems.append(f"no workbook for area(s): {', '.join(missing)}")
    return problems


# ---------------------------------------------------------------------------------------------
# Gallery JSON


def _query_item(book: Workbook, tab: Tab, index: int, item: Item) -> dict:
    settings = item.settings
    content: dict = {
        "version": "KqlItem/1.0",
        "query": item.query.replace("\n", "\r\n"),
        "size": 4 if item.kind == "tiles" else 0,
        "title": settings["title"],
        "noDataMessage": settings.get("empty", "No data in the selected time range."),
        "timeContext": {"durationMs": 0},
        "timeContextFromParameter": TIME_PARAMETER,
        **LOGS,
        "visualization": item.kind,
    }
    if item.kind == "tiles":
        tiles: dict = {
            "titleContent": {"columnMatch": settings["label"], "formatter": 1},
            "leftContent": {
                "columnMatch": settings["value"],
                "formatter": 12,
                "formatOptions": {"palette": "auto"},
                "numberFormat": {"unit": 17, "options": {"maximumSignificantDigits": 3, "maximumFractionDigits": 2}},
            },
            "showBorder": True,
        }
        if settings.get("note"):
            tiles["subtitleContent"] = {"columnMatch": settings["note"], "formatter": 1}
        content["tileSettings"] = tiles
    elif item.kind == "table":
        palette = settings.get("palette", "blue")
        formatters: list[dict] = []
        if settings.get("severity"):
            grid = [
                {"operator": "==", "thresholdValue": value, "representation": colour, "text": "{0}{1}"}
                for value, colour in SEVERITY_COLOURS
            ]
            grid.append({"operator": "Default", "thresholdValue": None, "representation": "blue", "text": "{0}{1}"})
            formatters.append({"columnMatch": settings["severity"], "formatter": 18,
                               "formatOptions": {"thresholdsOptions": "colors", "thresholdsGrid": grid}})  # fmt: skip
        for column in settings.get("bars", ()):
            formatters.append({"columnMatch": column, "formatter": 4, "formatOptions": {"min": 0, "palette": palette}})
        for column in settings.get("heat", ()):
            formatters.append({"columnMatch": column, "formatter": 8, "formatOptions": {"min": 0, "palette": palette}})
        if settings.get("link"):
            formatters.append({"columnMatch": settings["link"], "formatter": 7,
                               "formatOptions": {"linkTarget": "Url", "linkLabel": settings.get("link_label", "Open")}})  # fmt: skip
        for column in settings.get("hide", ()):
            formatters.append({"columnMatch": column, "formatter": 5})
        content["gridSettings"] = {"formatters": formatters, "filter": True, "rowLimit": int(settings.get("rows", 250))}
    elif settings.get("colours"):
        content["chartSettings"] = {
            "seriesLabelSettings": [{"seriesName": name, "color": colour} for name, colour in settings["colours"].items()]
        }
    return {
        "type": 3,
        "content": content,
        "customWidth": str(settings.get("width", 100)),
        "name": f"{tab.name} {index}".lower().replace(" ", "-"),
        "styleSettings": {"showBorder": True},
    }


def _text_item(tab: Tab, index: int, item: Item) -> dict:
    return {
        "type": 1,
        "content": {"json": str(item.settings["text"]).strip()},
        "customWidth": str(item.settings.get("width", 100)),
        "name": f"{tab.name} {index}".lower().replace(" ", "-"),
    }


def gallery(book: Workbook, rules: list[Rule]) -> dict:
    """The workbook as gallery template JSON: what the Advanced Editor in the portal accepts."""
    tabs = all_tabs(book, rules)
    needs = ", ".join(f"`{table}`" for table in book.tables)
    header = f"# {book.name}\n\n{book.intro}\n\n**Tables read:** {needs}"
    if book.optional_tables:
        header += " and, when present, " + ", ".join(f"`{table}`" for table in book.optional_tables)
    header += ". A tile or chart for a table you do not collect shows an error; the rest still works."
    items: list[dict] = [
        {"type": 1, "content": {"json": header}, "name": "introduction"},
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": _uuid(book.guid_seed, "parameter", TIME_PARAMETER),
                        "version": "KqlParameterItem/1.0",
                        "name": TIME_PARAMETER,
                        "label": "Time range",
                        "type": 4,
                        "isRequired": True,
                        "value": {"durationMs": RANGES_MS[book.default_range]},
                        "typeSettings": {
                            "selectableValues": [{"durationMs": value} for value in RANGES_MS.values()],
                            "allowCustom": True,
                        },
                    }
                ],
                "style": "pills",
                **LOGS,
            },
            "name": "parameters",
        },
        {
            "type": 11,
            "content": {
                "version": "LinkItem/1.0",
                "style": "tabs",
                "links": [
                    {
                        "id": _uuid(book.guid_seed, "tab", tab.name),
                        "cellValue": TAB_PARAMETER,
                        "linkTarget": "parameter",
                        "linkLabel": tab.name,
                        "subTarget": tab.name,
                        "style": "link",
                    }
                    for tab in tabs
                ],
            },
            "name": "tabs",
        },
    ]
    for tab in tabs:
        group_items = [
            _text_item(tab, index, item) if item.kind == "text" else _query_item(book, tab, index, item)
            for index, item in enumerate(tab.items, start=1)
        ]
        items.append(
            {
                "type": 12,
                "content": {"version": "NotebookGroup/1.0", "groupType": "editable", "items": group_items},
                "conditionalVisibility": {"parameterName": TAB_PARAMETER, "comparison": "isEqualTo", "value": tab.name},
                "name": f"tab-{tab.name}".lower().replace(" ", "-"),
            }
        )
    return {
        "version": "Notebook/1.0",
        "items": items,
        "fromTemplateId": "sentinel-UserWorkbook",
        "$schema": WORKBOOK_SCHEMA,
    }


def gallery_text(book: Workbook, rules: list[Rule]) -> str:
    return json.dumps(gallery(book, rules), indent=2, ensure_ascii=False) + "\n"
