"""A small KQL tokenizer and a name check against the table schemas.

This is not a KQL parser. It answers one question well: does every name in a query refer to
something that exists? A name must be a KQL keyword, a known function, a table in the schema
file, a column of a table the query reads, or a name the query itself defines. That catches the
mistakes that are easy to make and impossible to see by eye: a misspelt column, a column from the
wrong table, a function that does not exist.

It does not track which columns survive each pipeline stage (for example a column used after a
``summarize`` that dropped it). The semantic check in ``kql-check`` does that with Microsoft's own
parser; this check exists so the common mistakes are caught without installing anything.
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
    hourofday iff iif indexof ingestion_time ipv4_is_in_range ipv4_is_match ipv4_is_private
    isempty isnotempty isnotnull isnull make_bag make_list make_list_if make_set make_set_if
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
# query is checked. "{TimeRange:grain}" is the bucket size the workbook picks for the time range.
PLACEHOLDERS = {
    "{TimeRange:grain}": "1h",
}
_PLACEHOLDER = re.compile(r"\{[A-Za-z][A-Za-z0-9_]*(?::[A-Za-z]+)?\}")


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
    tables = data.get("tables")
    if not isinstance(tables, dict) or not tables:
        raise ValueError("the schema file has no tables")
    return tables


def fill_placeholders(query: str) -> str:
    """Replace workbook placeholders so the text is plain KQL. Unknown placeholders are an error."""

    def swap(match: re.Match[str]) -> str:
        found = match.group(0)
        if found not in PLACEHOLDERS:
            raise KqlError(f"unknown workbook placeholder {found}; allowed: {', '.join(sorted(PLACEHOLDERS))}")
        return PLACEHOLDERS[found]

    return _PLACEHOLDER.sub(swap, query)


def tokenize(query: str) -> list[Token]:
    """Split a query into tokens, dropping whitespace and comments."""
    tokens: list[Token] = []
    position = 0
    line = 1
    while position < len(query):
        match = _TOKEN.match(query, position)
        if match is None:
            raise KqlError(f"line {line}: unexpected character {query[position]!r}")
        kind = match.lastgroup or ""
        text = match.group(0)
        if kind not in ("space", "comment"):
            tokens.append(Token(kind, text, line))
        line += text.count("\n")
        position = match.end()
    return tokens


def strip_comments(query: str) -> str:
    """Return the query without comment lines and trailing comments, keeping line structure."""
    out: list[str] = []
    position = 0
    while position < len(query):
        match = _TOKEN.match(query, position)
        if match is None:
            raise KqlError(f"unexpected character {query[position]!r}")
        if match.lastgroup != "comment":
            out.append(match.group(0))
        position = match.end()
    lines = [line.rstrip() for line in "".join(out).split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


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
            if text in "([{":
                depth += 1
            elif text in ")]}":
                depth -= 1
            if in_parse and (text in "|;" and depth <= parse_depth or depth < parse_depth):
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


def check_names(query: str, schema: dict[str, dict[str, str]], workbook: bool = False) -> list[str]:
    """Return a list of problems with the names in a query. An empty list means none were found.

    Set workbook=True for a workbook query, which may contain the placeholders in PLACEHOLDERS.
    """
    try:
        tokens = tokenize(fill_placeholders(query) if workbook else query)
    except KqlError as error:
        return [str(error)]
    problems: list[str] = []
    depth = 0
    for token in tokens:
        if token.kind == "op" and token.text in "([{":
            depth += 1
        elif token.kind == "op" and token.text in ")]}":
            depth -= 1
            if depth < 0:
                return [f"line {token.line}: closing {token.text!r} without an opening one"]
    if depth != 0:
        problems.append("brackets are not balanced")

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
    return problems


def has_placeholder(tokens: list[Token]) -> bool:
    """True when the tokens contain a workbook placeholder such as {TimeRange} outside a string."""
    for index, token in enumerate(tokens[:-2]):
        if token.kind == "op" and token.text == "{" and tokens[index + 1].kind == "name":
            closing = tokens[index + 2].text
            if closing == "}" or (closing == ":" and index + 4 < len(tokens) and tokens[index + 4].text == "}"):
                return True
    return False


def names_in(query: str, workbook: bool = False) -> set[str]:
    """Every name that appears in the query; used to confirm a column is mentioned at all."""
    text = fill_placeholders(query) if workbook else query
    return {token.text for token in tokenize(text) if token.kind == "name"}


_AGO = re.compile(r"\bago\(\s*(\d+)\s*(d|h|m|s)\s*\)")
_UNIT_SECONDS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def longest_ago_seconds(query: str) -> int:
    """The longest literal ago(...) in the query, in seconds, or 0 when there is none."""
    text = strip_comments(query)
    return max((int(n) * _UNIT_SECONDS[u] for n, u in _AGO.findall(text)), default=0)
