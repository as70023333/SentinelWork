"""A small KQL tokenizer and a name check against the table schemas.

This is not a KQL parser. It answers one question well: does every name in a query refer to
something that exists? A name must be a KQL keyword, a known function, a table in the schema
file, a column of a table the query reads, or a name the query itself defines. That catches the
mistakes that are easy to make and impossible to see by eye: a misspelt column, a column from the
wrong table, a function that does not exist.

It is a spelling check, not a grammar check. It does not track which columns survive each
pipeline stage (a column used after the ``summarize`` that dropped it), and it does not notice a
misplaced operator. The semantic check in ``kql-check`` does both with Microsoft's own parser;
this check exists so the common mistakes are caught at once, without installing anything.

Only the KQL the content uses is understood. Obfuscated string literals (``h"..."``), user-defined
functions and a few rarer operators are reported as unknown; add support when a query needs it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "tables.json"

# Operators and other words that are part of the language rather than names.
KEYWORDS = frozenset(
    """
    and anti as asc bag bagexpansion between bool boolean by consume contains contains_cs count
    datatable datetime decimal default desc distinct double dynamic endswith endswith_cs evaluate
    extend false first from fullouter getschema guid has has_all has_any has_cs hasprefix
    hassuffix hint in inner innerunique int invoke isfuzzy join kind last leftanti leftouter
    leftsemi let limit long lookup make-series matches mv-apply mv-expand not null nulls of on or
    order parse parse-where print project project-away project-keep project-rename
    project-reorder range real regex render rightanti rightouter rightsemi sample search
    serialize shuffle sort startswith startswith_cs step strategy string summarize take timespan
    to top true typeof union where with withsource array $left $right
    """.split()
)

# Words that may be followed by "(" without being a function call.
PAREN_KEYWORDS = frozenset(
    """
    and anti between by datatable datetime dynamic fullouter has_all has_any in inner innerunique
    leftanti leftouter leftsemi not on or rightanti rightouter rightsemi timespan typeof union
    """.split()
)

# Scalar and aggregation functions the content is allowed to call. A function that is not listed
# here is reported, so a typo such as "tosting(" cannot slip through. Add to the list when a
# query needs a function that exists in Log Analytics.
FUNCTIONS = frozenset(
    """
    abs ago arg_max arg_min array_concat array_index_of array_length array_slice array_sort_asc
    avg avgif bag_has_key bag_keys bag_pack base64_decode_tostring bin bin_at case ceiling
    coalesce column_ifexists count countif countof datetime_add datetime_diff dayofweek dcount
    dcountif endofday extract extract_all floor format_datetime format_timespan gettype hash
    hourofday iff iif indexof ingestion_time ipv4_is_in_any_range ipv4_is_in_range ipv4_is_match
    ipv4_is_private isempty isnan isnotempty isnotnull isnull make_bag make_list make_list_if make_set make_set_if
    materialize max max_of maxif min min_of minif next not now pack pack_array parse_ipv4
    parse_json parse_path parse_url percentile prev replace_regex replace_string round row_number
    set_difference set_has_element set_intersect set_union split startofday startofmonth
    startofweek stdev strcat strcat_array strcat_delim strlen substring sum sumif take_any tobool
    todatetime todouble todynamic toint tolong tolower toreal toscalar tostring totimespan toupper
    trim trim_end trim_start url_decode
    """.split()
)

TYPE_NAMES = frozenset("string long int real double bool boolean datetime dynamic guid timespan decimal".split())

_HYPHENATED = (
    "mv-expand|mv-apply|project-away|project-keep|project-rename|project-reorder|make-series|parse-where"
)
_TOKEN = re.compile(
    r"""
      (?P<space>\s+)
    | (?P<comment>//[^\n]*)
    | (?P<string>@"(?:[^"]|"")*" | @'(?:[^']|'')*' | "(?:\\.|[^"\\\n])*" | '(?:\\.|[^'\\\n])*')
    | (?P<number>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[A-Za-z]*)
    | (?P<name>(?:%s)\b | [A-Za-z_$][A-Za-z0-9_]*)
    | (?P<op>==|!=|=~|!~|<=|>=|<>|\.\.|[-+*/%%<>=!~|,;:.()\[\]{}])
    """
    % _HYPHENATED,
    re.VERBOSE,
)

# Workbook placeholders that may appear inside a query, and the text used in their place when a
# query is checked. "{TimeRange:grain}" is the bucket size the workbook picks for the time range;
# start and end are the two ends of the range as datetime values.
PLACEHOLDERS = {
    "{TimeRange:grain}": "1h",
    "{TimeRange:start}": "datetime(2024-01-01)",
    "{TimeRange:end}": "datetime(2024-01-08)",
}
_PLACEHOLDER = re.compile(r"\{[A-Za-z][A-Za-z0-9_]*(?::[A-Za-z]+)?\}")
_BRACKETS = {")": "(", "]": "[", "}": "{"}
_TIMESPAN = re.compile(r"^(\d+(?:\.\d+)?)(d|h|m|s|ms)$")
_UNIT_SECONDS = {"d": 86400.0, "h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


class KqlError(ValueError):
    """A query could not be tokenized."""


@dataclass(frozen=True)
class Token:
    kind: str  # "string", "number", "name" or "op"
    text: str
    line: int


def load_schema(path: Path | None = None) -> dict[str, dict[str, str]]:
    """Return {table: {column: type}} from the schema file."""
    with open(path or SCHEMA_FILE, encoding="utf-8") as handle:
        data = json.load(handle)
    tables = data.get("tables") if isinstance(data, dict) else None
    if not isinstance(tables, dict) or not tables:
        raise ValueError("the schema file must be an object with a non-empty 'tables' object")
    for table, columns in tables.items():
        if not isinstance(columns, dict) or not all(isinstance(kind, str) for kind in columns.values()):
            raise ValueError(f"the schema file: table {table!r} must map column names to type names")
    return tables


def fill_placeholders(query: str) -> str:
    """Replace workbook placeholders so the text is plain KQL. Unknown placeholders are an error."""

    def swap(match: re.Match[str]) -> str:
        found = match.group(0)
        if found not in PLACEHOLDERS:
            raise KqlError(f"unknown workbook placeholder {found}; allowed: {', '.join(sorted(PLACEHOLDERS))}")
        return PLACEHOLDERS[found]

    return _PLACEHOLDER.sub(swap, query)


def _scan(query: str):
    """Yield (kind, text, line) for every piece of the query, including whitespace and comments."""
    position = 0
    line = 1
    while position < len(query):
        match = _TOKEN.match(query, position)
        if match is None:
            raise KqlError(f"line {line}: unexpected character {query[position]!r}")
        text = match.group(0)
        yield match.lastgroup or "", text, line
        line += text.count("\n")
        position = match.end()


def tokenize(query: str) -> list[Token]:
    """Split a query into tokens, dropping whitespace and comments."""
    return [Token(kind, text, line) for kind, text, line in _scan(query) if kind not in ("space", "comment")]


def strip_comments(query: str) -> str:
    """Return the query without comments. A line that held only a comment is removed entirely.

    No empty line is left behind: the Logs editor in the portal treats an empty line as the end of
    a query, so a query with one cannot be pasted there and run.
    """
    lines: list[str] = []
    current = ""
    comment_only = False
    for kind, text, _ in _scan(query):
        if kind == "comment":
            comment_only = not current.strip()
            continue
        pieces = text.split("\n")
        for index, piece in enumerate(pieces):
            if index:
                if not (comment_only and not current.strip()):
                    lines.append(current.rstrip())
                current = ""
                comment_only = False
            current += piece
    if not (comment_only and not current.strip()):
        lines.append(current.rstrip())
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def has_placeholder(query: str) -> bool:
    """True when the query contains a workbook placeholder such as {TimeRange} outside a string."""
    code = "".join(" " if kind in ("string", "comment") else text for kind, text, _ in _scan(query))
    return _PLACEHOLDER.search(code) is not None


def tables_used(tokens: list[Token], schema: dict[str, dict[str, str]]) -> list[str]:
    """Tables from the schema that the query reads, in order of first use."""
    seen: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind != "name" or token.text not in schema or token.text in seen:
            continue
        before = tokens[index - 1].text if index else ""
        after = tokens[index + 1].text if index + 1 < len(tokens) else ""
        if before == "." or after in ("=", ":"):
            continue  # a property, or a column the query happens to name like a table
        seen.append(token.text)
    return seen


def defined_names(tokens: list[Token]) -> set[str]:
    """Names the query introduces: let, extend, summarize, project, datatable and parse."""
    names: set[str] = set()
    in_parse = False
    after_with = False
    depth = 0
    parse_depth = 0
    for index, token in enumerate(tokens):
        text = token.text
        if token.kind == "op":
            if text in ("(", "[", "{"):
                depth += 1
            elif text in (")", "]", "}"):
                depth -= 1
            if in_parse and (text in ("|", ";") and depth <= parse_depth or depth < parse_depth):
                in_parse = after_with = False
            continue
        if token.kind != "name":
            continue
        after = tokens[index + 1] if index + 1 < len(tokens) else None
        before = tokens[index - 1] if index else None
        if text in ("parse", "parse-where") and (before is None or before.text == "|"):
            in_parse, after_with, parse_depth = True, False, depth
            continue
        if in_parse and text == "with" and depth == parse_depth:
            after_with = True
            continue
        if before is not None and before.text == ".":
            continue
        if in_parse and after_with and text not in TYPE_NAMES and text not in KEYWORDS:
            names.add(text)
            continue
        if after is None or after.kind != "op":
            continue
        if after.text == "=":
            names.add(text)
        elif after.text == ":" and index + 2 < len(tokens) and tokens[index + 2].text in TYPE_NAMES:
            names.add(text)
    return names


def _bracket_problem(tokens: list[Token]) -> str | None:
    """The first bracket that is not matched by one of its own kind, or None."""
    open_brackets: list[Token] = []
    for token in tokens:
        if token.kind != "op":
            continue
        if token.text in ("(", "[", "{"):
            open_brackets.append(token)
        elif token.text in _BRACKETS:
            if not open_brackets:
                return f"line {token.line}: closing {token.text!r} without an opening one"
            opened = open_brackets.pop()
            if opened.text != _BRACKETS[token.text]:
                return f"line {token.line}: {token.text!r} closes the {opened.text!r} opened on line {opened.line}"
    if open_brackets:
        return f"line {open_brackets[-1].line}: {open_brackets[-1].text!r} is never closed"
    return None


def check_names(query: str, schema: dict[str, dict[str, str]], workbook: bool = False, first_line: int = 1) -> list[str]:
    """Return a list of problems with the names in a query. An empty list means none were found.

    Set workbook=True for a workbook query, which may contain the placeholders in PLACEHOLDERS.
    first_line is the line of the file the query starts on, so reported lines are file lines.
    """
    try:
        tokens = tokenize(fill_placeholders(query) if workbook else query)
    except KqlError as error:
        return [_shift(str(error), first_line)]
    problems: list[str] = []
    brackets = _bracket_problem(tokens)
    if brackets:
        return [_shift(brackets, first_line)]

    used = tables_used(tokens, schema)
    if not used:
        problems.append("the query does not read any table from the schema file")
    columns: set[str] = set()
    for table in used:
        columns.update(schema[table])
    defined = defined_names(tokens)
    has_join = any(t.kind == "name" and t.text in ("join", "lookup") for t in tokens)

    for index, token in enumerate(tokens):
        if token.kind != "name":
            continue
        name = token.text
        before = tokens[index - 1].text if index else ""
        after = tokens[index + 1].text if index + 1 < len(tokens) else ""
        if before == ".":
            continue  # a property of a dynamic value, not a column
        if after == "(":
            if name in FUNCTIONS or name in PAREN_KEYWORDS:
                continue
            if name in defined:
                continue  # "in (SomeLetName)" style use of a let statement
            if name in KEYWORDS and name not in FUNCTIONS:
                continue
            problems.append(f"line {token.line}: unknown function {name}()")
            continue
        if name in KEYWORDS or name in TYPE_NAMES or name in schema or name in columns or name in defined:
            continue
        if has_join and name[-1:] == "1" and (name[:-1] in columns or name[:-1] in defined):
            continue  # the right-hand copy of a column after a join
        if name in FUNCTIONS:
            problems.append(f"line {token.line}: function {name} is used without ()")
            continue
        hint = ""
        if used:
            hint = f" (tables read: {', '.join(used)})"
        problems.append(f"line {token.line}: unknown name {name}{hint}")
    return [_shift(problem, first_line) for problem in problems]


def _shift(problem: str, first_line: int) -> str:
    """Turn 'line N' counted from the start of the query into the line of the file."""
    match = re.match(r"line (\d+)", problem)
    if match is None or first_line == 1:
        return problem
    return f"line {int(match.group(1)) + first_line - 1}{problem[match.end():]}"


def names_in(query: str, workbook: bool = False) -> set[str]:
    """Every name that appears in the query; used to confirm a column is mentioned at all."""
    text = fill_placeholders(query) if workbook else query
    return {token.text for token in tokenize(text) if token.kind == "name"}


def _timespan_seconds(text: str) -> float | None:
    match = _TIMESPAN.match(text)
    return float(match.group(1)) * _UNIT_SECONDS[match.group(2)] if match else None


def lookback(query: str) -> tuple[float, list[str]]:
    """How far back the query reaches, in seconds, and anything that could not be worked out.

    Sentinel only gives a rule the data of its Period, so a rule must not look back further.
    Understood: ago(1h), ago(Name) where "let Name = 1h;" and now() - 1h (or - Name). Anything else
    inside ago(), and now() with an offset, is reported: a check that cannot read the value must
    say so, not assume it is fine.
    """
    tokens = tokenize(query)
    timespans: dict[str, float] = {}
    for index, token in enumerate(tokens[:-4]):
        if token.kind == "name" and token.text == "let" and tokens[index + 2].text == "=" and tokens[index + 4].text == ";":
            seconds = _timespan_seconds(tokens[index + 3].text)
            if seconds is not None:
                timespans[tokens[index + 1].text] = seconds

    def value(token: Token) -> float | None:
        if token.kind == "number":
            return _timespan_seconds(token.text)
        return timespans.get(token.text) if token.kind == "name" else None

    longest = 0.0
    problems: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind != "name" or index + 1 >= len(tokens) or tokens[index + 1].text != "(":
            continue
        if index and tokens[index - 1].text == ".":
            continue
        if token.text == "ago":
            inside = tokens[index + 2] if index + 2 < len(tokens) else None
            closes = index + 3 < len(tokens) and tokens[index + 3].text == ")"
            seconds = value(inside) if inside is not None and closes else None
            if seconds is None:
                problems.append(f"line {token.line}: cannot tell how far ago(...) looks back; use a literal such as "
                                "ago(1h) or a name set with 'let Name = 1h;'")  # fmt: skip
            else:
                longest = max(longest, seconds)
        elif token.text == "now":
            if index + 2 >= len(tokens) or tokens[index + 2].text != ")":
                problems.append(f"line {token.line}: now() with an offset is not understood; use ago(...)")
            elif index + 4 < len(tokens) and tokens[index + 3].text == "-":
                seconds = value(tokens[index + 4])
                if seconds is not None:
                    longest = max(longest, seconds)
    return longest, problems
