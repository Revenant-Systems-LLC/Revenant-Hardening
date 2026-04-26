using RevenantHardening.Core.Models;

namespace RevenantHardening.Core.Reporters;

public sealed class ConsoleReporter(bool roastMode = false) : IReporter
{
    public void Report(ScanResult result, TextWriter output)
    {
        var prev = Console.ForegroundColor;

        WriteBanner(output);
        output.WriteLine($"  Scan root : {result.ScanRoot}");
        output.WriteLine($"  Files     : {result.FilesScanned}");
        output.WriteLine($"  Duration  : {result.Duration.TotalSeconds:F2}s");
        output.WriteLine();

        if (result.Findings.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            output.WriteLine(roastMode
                ? "  No findings. Either your app is clean or you're lucky. Probably lucky."
                : "  No findings. Good job.");
            Console.ForegroundColor = prev;
            output.WriteLine();
        }
        else
        {
            foreach (var finding in result.Findings)
                WriteFinding(finding, output, prev);
        }

        WriteSummary(result, output, prev);
        Console.ForegroundColor = prev;
    }

    private static void WriteBanner(TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("  RSH — Revenant Hardening Scanner");
        output.WriteLine("  " + new string('─', 50));
        output.WriteLine();
    }

    private static void WriteFinding(Finding finding, TextWriter output, ConsoleColor prev)
    {
        Console.ForegroundColor = SeverityColor(finding.Severity);
        output.WriteLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.RuleId}  {finding.Title}");
        Console.ForegroundColor = prev;
        output.WriteLine($"File: {finding.File}{(finding.Line.HasValue ? $":{finding.Line}" : "")}");
        output.WriteLine();
        output.WriteLine("Why this matters:");
        output.WriteLine($"  {finding.Why}");
        output.WriteLine();
        output.WriteLine("Fix:");
        output.WriteLine($"  {finding.Fix}");
        output.WriteLine();
        output.WriteLine("  " + new string('·', 50));
        output.WriteLine();
    }

    private void WriteSummary(ScanResult result, TextWriter output, ConsoleColor prev)
    {
        var counts = result.Findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        output.WriteLine("  " + new string('═', 50));
        output.WriteLine();

        Console.ForegroundColor = GradeColor(result.Grade);
        output.WriteLine($"  Score : {result.Score}/100   Grade : {result.Grade}");
        Console.ForegroundColor = prev;
        output.WriteLine();

        void Count(Severity s)
        {
            var n = counts.GetValueOrDefault(s, 0);
            if (n == 0) return;
            Console.ForegroundColor = SeverityColor(s);
            output.WriteLine($"  {s,-10} {n}");
            Console.ForegroundColor = prev;
        }

        Count(Severity.Critical);
        Count(Severity.High);
        Count(Severity.Medium);
        Count(Severity.Low);

        output.WriteLine();

        if (roastMode)
            WriteRoast(result, output);

        output.WriteLine();
    }

    private static void WriteRoast(ScanResult result, TextWriter output)
    {
        var msg = result.Grade switch
        {
            'A' => "Clean build. Ship it. Carefully.",
            'B' => "Not bad. A few rough edges, but you're not embarrassing yourself.",
            'C' => "Your AI assistant phoned this one in. So did you for not reviewing it.",
            'D' => "This app would last approximately 11 minutes on a corporate network.",
            _ => "Congratulations. You vibe-coded a security incident. Classic."
        };
        output.WriteLine($"  {msg}");
    }

    private static ConsoleColor SeverityColor(Severity s) => s switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.High => ConsoleColor.DarkYellow,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.Gray,
        _ => ConsoleColor.White
    };

    private static ConsoleColor GradeColor(char grade) => grade switch
    {
        'A' => ConsoleColor.Green,
        'B' => ConsoleColor.Cyan,
        'C' => ConsoleColor.Yellow,
        'D' => ConsoleColor.DarkYellow,
        _ => ConsoleColor.Red
    };
}
