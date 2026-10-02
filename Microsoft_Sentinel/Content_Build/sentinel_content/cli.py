"""Command line: python -m sentinel_content <build | check | list | export-queries>."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, build
from .kql import KqlError
from .rules import AREAS, CONTENT_ROOT, RuleError
from .workbooks import WorkbookError, workbook_queries

EXIT_OK, EXIT_PROBLEMS, EXIT_ERROR = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel_content",
        description="Build and check the Sentinel detection rules and workbooks in this repository.",
    )
    parser.add_argument("--version", action="version", version=f"sentinel_content {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build", help="check the sources, then write the templates, workbooks and catalogue")
    make.add_argument("--enabled", action="store_true",
                      help="write rule templates whose rules start enabled; needs --out so the committed "
                           "templates (rules disabled) are left alone")  # fmt: skip
    make.add_argument("--out", metavar="DIR", help="write the generated files under DIR instead of the repository")
    commands.add_parser("check", help="check the sources and confirm the generated files are up to date")
    commands.add_parser("list", help="list the rules and workbooks")
    export = commands.add_parser("export-queries", help="write every query as JSON for the kql-check tool")
    export.add_argument("file", help="file to write")
    return parser


def _report(problems: list[str]) -> None:
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)


def run(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rules, books, schema = build.load_all()
    found = build.problems(rules, books, schema)

    if args.command == "list":
        for area, details in AREAS.items():
            book = next((b for b in books if b.area == area), None)
            print(f"{details['title']}: workbook {book.name if book else '(none)'}")
            for rule in (r for r in rules if r.area == area):
                print(f"  {rule.id}  {rule.severity:<13}  {rule.title}")
        print(f"\n{len(rules)} rules, {len(books)} workbooks, "
              f"{sum(len(workbook_queries(b, rules)) for b in books)} workbook queries")  # fmt: skip
        return EXIT_OK

    if found:
        print(f"{len(found)} problem(s) in the sources:", file=sys.stderr)
        _report(found)
        return EXIT_PROBLEMS

    if args.command == "export-queries":
        Path(args.file).write_text(build.query_export(rules, books), encoding="utf-8", newline="\n")
        print(f"wrote {args.file}")
        return EXIT_OK

    if args.command == "build":
        if args.enabled and not args.out:
            print("--enabled needs --out DIR: the templates in the repository keep their rules disabled", file=sys.stderr)
            return EXIT_ERROR
        if args.out is not None and not args.out.strip():
            print("--out needs a folder name", file=sys.stderr)
            return EXIT_ERROR
        root = Path(args.out) if args.out else CONTENT_ROOT
        if args.enabled and root.resolve() == CONTENT_ROOT.resolve():
            print("--out must be a different folder: the templates in the repository keep their rules disabled",
                  file=sys.stderr)  # fmt: skip
            return EXIT_ERROR
        changed = build.write_files(build.generated_files(rules, books, enabled=args.enabled), root)
        for relative in changed:
            print(f"wrote {relative.as_posix()}")
        print(f"{len(rules)} rules and {len(books)} workbooks built; {len(changed)} file(s) changed under {root}")
        return EXIT_OK

    stale = build.stale_files(build.generated_files(rules, books), CONTENT_ROOT)
    if stale:
        print("generated files do not match the sources; run: python -m sentinel_content build", file=sys.stderr)
        _report(stale)
        return EXIT_PROBLEMS
    print(f"ok: {len(rules)} rules, {len(books)} workbooks, generated files are up to date")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        code = run(argv)
        if sys.stdout is not None:
            sys.stdout.flush()
        return code
    except BrokenPipeError:
        return EXIT_OK
    except (RuleError, WorkbookError, KqlError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as error:  # a bug in this tool: still exit 2, never 1 ("problems found")
        print(f"error: unexpected {type(error).__name__}: {error}", file=sys.stderr)
        return EXIT_ERROR
