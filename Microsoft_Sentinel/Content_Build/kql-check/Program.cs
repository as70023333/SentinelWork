// Checks every query in this repository with Microsoft's KQL parser (Kusto.Language).
//
// The Python linter confirms that names exist. This goes further: it parses each query the way
// Azure does and analyses it against the table schemas, so it also catches a column used after
// the stage that removed it, a function called with the wrong arguments, or a type mismatch.
// It then checks that the result of each query has the columns the rule or workbook relies on.
//
// Usage: KqlCheck <schema/tables.json> <queries.json>
// queries.json is written by: python -m sentinel_content export-queries <file>
// Exit code 0: every query is clean. 1: at least one problem. 2: the tool could not run.

using System.Text;
using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

namespace KqlCheck;

internal static class Program
{
    private const int MaxAnnotations = 8;
    private const int MaxAnnotationLength = 6000;

    private static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("usage: KqlCheck <schema/tables.json> <queries.json>");
            return 2;
        }

        GlobalState globals;
        int tableCount;
        try
        {
            globals = LoadSchema(args[0], out tableCount);
        }
        catch (Exception error)
        {
            Fail("kql-check could not read the schema", error.Message);
            return 2;
        }

        string selfTest = SelfTest(globals);
        if (selfTest != null)
        {
            Fail("kql-check self-test failed", selfTest);
            return 2;
        }

        var failures = new List<string>();
        var warnings = new List<string>();
        int queryCount = 0;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(args[1]));
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                queryCount++;
                string id = entry.GetProperty("id").GetString() ?? "";
                string source = entry.GetProperty("source").GetString() ?? "";
                string query = entry.GetProperty("query").GetString() ?? "";
                var required = Strings(entry, "columns");
                var exact = Strings(entry, "exact");
                var numeric = Strings(entry, "numeric");
                CheckQuery(globals, id, source, query, required, exact, numeric, failures, warnings);
            }
        }
        catch (Exception error)
        {
            Fail("kql-check could not read the queries", error.Message);
            return 2;
        }

        if (queryCount == 0)
        {
            Fail("kql-check found nothing to check", "the queries file is empty");
            return 2;
        }

        string version = typeof(KustoCode).Assembly.GetName().Version?.ToString() ?? "unknown";
        string summary = $"{queryCount} queries analysed against {tableCount} tables with Kusto.Language {version}: " +
                         $"{failures.Count} problem(s), {warnings.Count} warning(s). Self-test: 9 deliberately broken " +
                         "queries rejected, 1 correct query accepted.";
        Console.WriteLine(summary);

        foreach (var warning in warnings)
        {
            Console.WriteLine("warning: " + warning);
        }

        if (failures.Count == 0)
        {
            Console.WriteLine("::notice title=KQL semantic check passed::" + Escape(summary));
            if (warnings.Count > 0)
            {
                Annotate("warning", "KQL warnings", warnings);
            }
            return 0;
        }

        foreach (var failure in failures)
        {
            Console.WriteLine("problem: " + failure);
        }
        failures.Insert(0, summary);
        Annotate("error", "KQL semantic check failed", failures);
        return 1;
    }

    private static GlobalState LoadSchema(string path, out int tableCount)
    {
        var tables = new List<Symbol>();
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var table in document.RootElement.GetProperty("tables").EnumerateObject())
        {
            var columns = new List<ColumnSymbol>();
            foreach (var column in table.Value.EnumerateObject())
            {
                string typeName = column.Value.GetString() ?? "";
                ScalarSymbol type = ScalarTypes.GetSymbol(typeName);
                if (type == null)
                {
                    throw new InvalidDataException($"{table.Name}.{column.Name}: unknown type '{typeName}'");
                }
                columns.Add(new ColumnSymbol(column.Name, type));
            }
            tables.Add(new TableSymbol(table.Name, columns));
        }
        tableCount = tables.Count;
        if (tableCount == 0)
        {
            throw new InvalidDataException("the schema file has no tables");
        }
        return GlobalState.Default.WithDatabase(new DatabaseSymbol("workspace", tables));
    }

    // Proves on every run that the analysis is switched on: each of these queries is wrong in a
    // different way and must be rejected, and the correct one must pass. Without this, a schema
    // that failed to load or a library change could turn the whole check into a silent pass.
    private static string SelfTest(GlobalState globals)
    {
        var broken = new (string Query, string Why)[]
        {
            ("SigninLogs | where NoSuchColumn == 'x'", "a column that does not exist"),
            ("SigninLogs | summarize Total = count() by IPAddress | where UserPrincipalName == 'x'",
                "a column used after summarize removed it"),
            ("SigninLogs | extend Value = no_such_function(IPAddress)", "a function that does not exist"),
            ("NoSuchTable | take 1", "a table that does not exist"),
            ("SigninLogs | where IPAddress ==", "a query that is not complete"),
            ("SigninLogs | extend Value = strcat_array(IPAddress)", "a function called with too few arguments"),
        };
        var none = new List<string>();
        foreach (var (query, why) in broken)
        {
            var failures = new List<string>();
            CheckQuery(globals, "self-test", "self-test", query, none, none, none, failures, new List<string>());
            if (failures.Count == 0)
            {
                return $"a query with {why} was accepted: {query}";
            }
        }

        var missing = new List<string>();
        CheckQuery(globals, "self-test", "self-test", "SigninLogs | project IPAddress",
            new List<string> { "UserPrincipalName" }, none, none, missing, new List<string>());
        if (missing.Count != 1)
        {
            return "a result without a required column was accepted";
        }

        var clash = new List<string>();
        CheckQuery(globals, "self-test", "self-test", "SigninLogs | project Risk = RiskLevelDuringSignIn, RiskState",
            none, new List<string> { "Risk" }, none, clash, new List<string>());
        if (clash.Count != 1)
        {
            return "a formatted column whose name is part of another column name was accepted";
        }

        var text = new List<string>();
        CheckQuery(globals, "self-test", "self-test", "SigninLogs | summarize Total = count() by IPAddress",
            none, none, new List<string> { "IPAddress" }, text, new List<string>());
        if (text.Count != 1)
        {
            return "a text column formatted as a number was accepted";
        }

        var clean = new List<string>();
        CheckQuery(globals, "self-test", "self-test",
            "SigninLogs | where ResultType == '0' | summarize SignIns = count() by IPAddress | top 5 by SignIns desc",
            new List<string> { "IPAddress", "SignIns" }, new List<string> { "SignIns" },
            new List<string> { "SignIns" }, clean, new List<string>());
        if (clean.Count != 0)
        {
            return "a correct query was rejected: " + string.Join("; ", clean);
        }
        return null;
    }

    private static void CheckQuery(GlobalState globals, string id, string source, string query,
        List<string> required, List<string> exact, List<string> numeric, List<string> failures, List<string> warnings)
    {
        KustoCode code = KustoCode.ParseAndAnalyze(query, globals);
        bool hasError = false;
        foreach (var diagnostic in code.GetDiagnostics())
        {
            string where = "";
            if (diagnostic.HasLocation && code.TryGetLineAndOffset(diagnostic.Start, out int line, out int offset))
            {
                int end = Math.Min(query.Length, diagnostic.Start + Math.Max(diagnostic.Length, 1));
                string text = diagnostic.Start < query.Length ? query.Substring(diagnostic.Start, end - diagnostic.Start) : "";
                text = text.Replace("\r", " ").Replace("\n", " ");
                if (text.Length > 60)
                {
                    text = text.Substring(0, 60) + "...";
                }
                where = $" at line {line}, column {offset} near '{text}'";
            }
            string message = $"[{id}] ({source}) {diagnostic.Code}: {diagnostic.Message}{where}";
            if (diagnostic.Severity == DiagnosticSeverity.Error)
            {
                hasError = true;
                failures.Add(message);
            }
            else if (diagnostic.Severity == DiagnosticSeverity.Warning)
            {
                warnings.Add(message);
            }
        }

        if (hasError)
        {
            return;
        }

        if (code.ResultType is not TableSymbol result)
        {
            failures.Add($"[{id}] ({source}) the query does not return a table");
            return;
        }

        var names = result.Columns.Select(column => column.Name).ToList();
        foreach (string column in required)
        {
            if (!names.Contains(column))
            {
                failures.Add($"[{id}] ({source}) the result has no column '{column}'. It has: {string.Join(", ", names)}");
            }
        }
        foreach (string column in numeric)
        {
            ColumnSymbol found = result.Columns.FirstOrDefault(candidate => candidate.Name == column);
            if (found != null && !IsNumber(found.Type))
            {
                failures.Add($"[{id}] ({source}) column '{column}' is shown as a number, bar or shading but its type is " +
                             $"{found.Type.Name}");
            }
        }
        foreach (string column in exact)
        {
            foreach (string other in names)
            {
                if (other != column && other.Contains(column, StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add($"[{id}] ({source}) column '{column}' is formatted in the workbook and column " +
                                 $"'{other}' contains its name, so it could pick up the same formatting; rename one");
                }
            }
        }
    }

    private static bool IsNumber(TypeSymbol type)
    {
        return type == ScalarTypes.Long || type == ScalarTypes.Int || type == ScalarTypes.Real || type == ScalarTypes.Decimal;
    }

    // A missing list is an error, not "nothing to check": the export and this tool must agree.
    private static List<string> Strings(JsonElement entry, string property)
    {
        var values = new List<string>();
        foreach (var item in entry.GetProperty(property).EnumerateArray())
        {
            string value = item.GetString();
            if (!string.IsNullOrEmpty(value))
            {
                values.Add(value);
            }
        }
        return values;
    }

    // GitHub shows at most ten annotations of a kind per step, so the lines are packed into a few.
    private static void Annotate(string level, string title, List<string> lines)
    {
        var chunk = new StringBuilder();
        int written = 0;
        int index = 0;
        while (index < lines.Count && written < MaxAnnotations)
        {
            string line = lines[index];
            if (line.Length > MaxAnnotationLength - 200)
            {
                line = line.Substring(0, MaxAnnotationLength - 200) + "...";
            }
            if (chunk.Length > 0 && chunk.Length + line.Length + 1 > MaxAnnotationLength)
            {
                Console.WriteLine($"::{level} title={title} ({written + 1})::" + Escape(chunk.ToString()));
                written++;
                chunk.Clear();
                continue;
            }
            if (chunk.Length > 0)
            {
                chunk.Append('\n');
            }
            chunk.Append(line);
            index++;
        }
        if (chunk.Length > 0 && written < MaxAnnotations)
        {
            Console.WriteLine($"::{level} title={title} ({written + 1})::" + Escape(chunk.ToString()));
        }
        if (index < lines.Count)
        {
            Console.WriteLine($"::{level} title={title} (more)::{lines.Count - index} more line(s) are in the job log.");
        }
    }

    private static void Fail(string title, string message)
    {
        Console.Error.WriteLine(title + ": " + message);
        Console.WriteLine($"::error title={title}::" + Escape(message));
    }

    private static string Escape(string text)
    {
        return text.Replace("%", "%25").Replace("\r", "%0D").Replace("\n", "%0A");
    }
}
