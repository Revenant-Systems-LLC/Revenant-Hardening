using System.Net;
using System.Text;
using RevenantHardening.Core.Models;

namespace RevenantHardening.Core.Reporters;

public sealed class HtmlReporter : IReporter
{
    public void Report(ScanResult result, TextWriter output)
    {
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("<title>RSH Report</title>");
        sb.AppendLine(Css());
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        sb.AppendLine("<div class=\"container\">");
        sb.AppendLine("<h1>Revenant Hardening Report</h1>");

        AppendSummaryCard(sb, result);
        AppendFindings(sb, result);

        sb.AppendLine("</div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        output.Write(sb.ToString());
    }

    private static void AppendSummaryCard(StringBuilder sb, ScanResult result)
    {
        var gradeClass = result.Grade switch
        {
            'A' => "grade-a",
            'B' => "grade-b",
            'C' => "grade-c",
            'D' => "grade-d",
            _ => "grade-f"
        };

        sb.AppendLine($"<div class=\"summary-card\">");
        sb.AppendLine($"  <div class=\"grade {gradeClass}\">{result.Grade}</div>");
        sb.AppendLine($"  <div class=\"summary-details\">");
        sb.AppendLine($"    <p><strong>Score:</strong> {result.Score}/100</p>");
        sb.AppendLine($"    <p><strong>Scan root:</strong> {WebUtility.HtmlEncode(result.ScanRoot)}</p>");
        sb.AppendLine($"    <p><strong>Files scanned:</strong> {result.FilesScanned}</p>");
        sb.AppendLine($"    <p><strong>Duration:</strong> {result.Duration.TotalSeconds:F2}s</p>");
        sb.AppendLine($"    <p><strong>Findings:</strong> {result.Findings.Count}</p>");

        var bySeverity = result.Findings.GroupBy(f => f.Severity).ToDictionary(g => g.Key, g => g.Count());
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            if (bySeverity.TryGetValue(sev, out var count))
                sb.AppendLine($"    <p><span class=\"badge badge-{sev.ToString().ToLowerInvariant()}\">{sev}: {count}</span></p>");
        }

        sb.AppendLine($"  </div>");
        sb.AppendLine($"</div>");
    }

    private static void AppendFindings(StringBuilder sb, ScanResult result)
    {
        if (result.Findings.Count == 0)
        {
            sb.AppendLine("<p class=\"no-findings\">No findings. Clean scan.</p>");
            return;
        }

        sb.AppendLine("<h2>Findings</h2>");

        foreach (var finding in result.Findings)
        {
            var sevClass = finding.Severity.ToString().ToLowerInvariant();
            sb.AppendLine($"<div class=\"finding finding-{sevClass}\">");
            sb.AppendLine($"  <div class=\"finding-header\">");
            sb.AppendLine($"    <span class=\"badge badge-{sevClass}\">{finding.Severity.ToString().ToUpperInvariant()}</span>");
            sb.AppendLine($"    <span class=\"rule-id\">{WebUtility.HtmlEncode(finding.RuleId)}</span>");
            sb.AppendLine($"    <span class=\"rule-title\">{WebUtility.HtmlEncode(finding.Title)}</span>");
            sb.AppendLine($"  </div>");
            sb.AppendLine($"  <p class=\"finding-file\">📄 {WebUtility.HtmlEncode(finding.File)}{(finding.Line.HasValue ? $":{finding.Line}" : "")}</p>");
            sb.AppendLine($"  <div class=\"finding-body\">");
            sb.AppendLine($"    <p><strong>Why this matters:</strong> {WebUtility.HtmlEncode(finding.Why)}</p>");
            sb.AppendLine($"    <p><strong>Fix:</strong> {WebUtility.HtmlEncode(finding.Fix)}</p>");
            sb.AppendLine($"  </div>");
            sb.AppendLine($"</div>");
        }
    }

    private static string Css() => """
        <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
               background: #0f0f0f; color: #e0e0e0; line-height: 1.6; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { font-size: 1.8rem; font-weight: 700; margin-bottom: 1.5rem; color: #f0f0f0; }
        h2 { font-size: 1.3rem; font-weight: 600; margin: 2rem 0 1rem; color: #c0c0c0; }
        .summary-card { display: flex; gap: 1.5rem; align-items: flex-start;
                        background: #1a1a1a; border: 1px solid #333; border-radius: 8px;
                        padding: 1.5rem; margin-bottom: 2rem; }
        .grade { font-size: 4rem; font-weight: 900; width: 80px; text-align: center; line-height: 1; }
        .grade-a { color: #4caf50; }
        .grade-b { color: #8bc34a; }
        .grade-c { color: #ffc107; }
        .grade-d { color: #ff9800; }
        .grade-f { color: #f44336; }
        .summary-details p { margin: 0.25rem 0; font-size: 0.9rem; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
                 font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .badge-critical { background: #b71c1c; color: #fff; }
        .badge-high     { background: #e65100; color: #fff; }
        .badge-medium   { background: #f57f17; color: #000; }
        .badge-low      { background: #455a64; color: #fff; }
        .finding { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px;
                   margin-bottom: 1rem; padding: 1rem; }
        .finding-critical { border-left: 4px solid #f44336; }
        .finding-high     { border-left: 4px solid #ff9800; }
        .finding-medium   { border-left: 4px solid #ffc107; }
        .finding-low      { border-left: 4px solid #607d8b; }
        .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
        .rule-id    { font-family: monospace; font-size: 0.85rem; color: #aaa; }
        .rule-title { font-weight: 600; color: #eee; }
        .finding-file { font-family: monospace; font-size: 0.8rem; color: #888; margin-bottom: 0.75rem; }
        .finding-body p { font-size: 0.9rem; margin-bottom: 0.4rem; }
        .no-findings { color: #4caf50; font-weight: 600; margin-top: 1rem; }
        </style>
        """;
}
