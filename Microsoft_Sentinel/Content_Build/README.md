# Content build

The tool that turns the readable sources in this repository into the files Microsoft Sentinel
accepts, and checks them on the way.

| Source (edit these) | Generated (do not edit) |
|---|---|
| [../Detection-rules/](../Detection-rules/)`<area>/<Id>-<name>.kql` | `../Detection-rules/deploy/all-rules.json`, one `deploy/<area>.json` per area, `../Detection-rules/CATALOGUE.md` |
| [../Workbooks/src/](../Workbooks/src/)`<area>.toml` | `../Workbooks/<Name>.json` (gallery template), `../Workbooks/deploy/all-workbooks.json` |

Python 3.11 or newer, standard library only. Nothing to install.

## Commands

Run them from this folder.

```bash
python -m sentinel_content list              # the rules and workbooks, by area
python -m sentinel_content check             # are the sources valid and the generated files current?
python -m sentinel_content build             # check, then rewrite the generated files
python -m unittest discover -s tests -t .    # the tests
```

`build` writes nothing if `check` finds a problem; it prints the problems instead, each with the
file and, for a query, the line. Exit codes: 0 success, 1 problems found, 2 the command could not
run.

Two more, used less often:

```bash
python -m sentinel_content build --enabled --out <folder>   # templates whose rules start enabled
python -m sentinel_content export-queries <file.json>       # every query, for the semantic check
```

`--enabled` needs `--out` so that the templates committed here always keep their rules disabled.

## What is checked

**For every rule** ([sentinel_content/rules.py](sentinel_content/rules.py)): the header has the
required fields and no unknown ones; the Id matches the folder and the file name; severity,
tactics, trigger and alert grouping are values the Sentinel API accepts; each technique belongs to
one of the listed tactics; frequency and period are valid durations between 5 minutes and 14 days,
the period covers the frequency, and the query does not look back further than the period; entity
types and identifiers exist; mapped columns appear in the query; incident grouping refers to
entities and custom details the rule defines; the tables listed are the tables the query reads;
Ids and titles are unique.

**For every workbook** ([sentinel_content/workbooks.py](sentinel_content/workbooks.py)): settings
and item kinds are known; every query item has a title and a query; columns named in formatting
appear in the query; the tables listed are the tables read; there is exactly one workbook per area.

**For every query** ([sentinel_content/kql.py](sentinel_content/kql.py)): every name must be a KQL
keyword, a function on the allowed list, a table in the schema file, a column of a table the query
reads, or a name the query defines itself. A misspelt column or a column from the wrong table is
reported with its line number.

**Generated files**: `check` rebuilds everything in memory and compares it with what is on disk,
so a source cannot be committed without its outputs.

## The semantic check

The name check does not follow columns through the pipeline. [kql-check/](kql-check/) does: a small
C# program that loads the same schema file into Microsoft's KQL parser (the
`Microsoft.Azure.Kusto.Language` package, the library behind the Azure query editors), then parses
and analyses every query. It reports syntax errors, unknown names, wrong argument counts and
columns used after the stage that removed them, and it confirms the result of each query contains
the columns the rule maps or the workbook formats.

It runs in CI on every push. To run it yourself you need the .NET 8 SDK:

```bash
python -m sentinel_content export-queries /tmp/queries.json
dotnet run --project kql-check --configuration Release -- schema/tables.json /tmp/queries.json
```

Before it looks at the real queries it analyses eight deliberately broken ones and one correct one.
If a broken query is accepted, the run fails. That is what makes "0 problems" mean something.

## The schema file

[schema/tables.json](schema/tables.json) holds the column names and types of the 21 tables the
content reads, copied from the Microsoft Learn table reference in October 2026. To use a table or
column that is not there, add it from the reference page
(`https://learn.microsoft.com/azure/azure-monitor/reference/tables/<table>`). Both checks read
this one file.

To use a KQL function that is not on the allowed list, add it to `FUNCTIONS` in
[sentinel_content/kql.py](sentinel_content/kql.py). The list is deliberate: an unknown function is
far more often a typo than a new function.

## Layout

```
Content_Build/
  sentinel_content/
    kql.py         tokenizer and name check
    rules.py       rule files -> rule objects -> Sentinel alert rule properties
    workbooks.py   workbook sources -> gallery JSON, and the generated Detections tab
    arm.py         ARM templates for rules and workbooks
    build.py       the list of generated files, the catalogue, the query export
    cli.py         the commands
  schema/tables.json
  kql-check/       the semantic check (C#)
  tests/           unit tests; they also run the checks over the real rules and workbooks
```

CI is [.github/workflows/sentinel-content.yml](../../.github/workflows/sentinel-content.yml): the
tests and `check` on Python 3.11, 3.12 and 3.13, and the semantic check.
