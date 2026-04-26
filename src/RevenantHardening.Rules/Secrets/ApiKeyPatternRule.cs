using System.Text.RegularExpressions;
using RevenantHardening.Core;
using RevenantHardening.Core.Models;

namespace RevenantHardening.Rules.Secrets;

/// <summary>RSH-SEC-001: Hardcoded API key/token pattern.</summary>
public sealed partial class ApiKeyPatternRule : IRule
{
    [GeneratedRegex(@"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[""']?[A-Za-z0-9+/\-_]{20,}[""']?")]
    private static partial Regex ApiKeyPattern();

    [GeneratedRegex(@"sk-[A-Za-z0-9]{20,}")]
    private static partial Regex OpenAiKeyPattern();

    [GeneratedRegex(@"ghp_[A-Za-z0-9]{36}")]
    private static partial Regex GithubPatPattern();

    [GeneratedRegex(@"AKIA[0-9A-Z]{16}")]
    private static partial Regex AwsKeyPattern();

    [GeneratedRegex(@"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")]
    private static partial Regex BearerTokenPattern();

    private static readonly (Regex Pattern, string Label)[] Patterns =
    [
        (ApiKeyPattern(),       "API key/secret"),
        (OpenAiKeyPattern(),    "OpenAI-style key"),
        (GithubPatPattern(),    "GitHub PAT"),
        (AwsKeyPattern(),       "AWS access key"),
        (BearerTokenPattern(),  "Bearer token"),
    ];

    public RuleMetadata Metadata { get; } = new(
        Id: "RSH-SEC-001",
        Title: "Hardcoded API key/token pattern",
        DefaultSeverity: Severity.Critical,
        FileExtensions: [".cs", ".xaml", ".resx", ".csproj", ".props", ".targets", ".json", ".config", ".xml"]
    );

    public IEnumerable<Finding> Analyze(FileContext context)
    {
        foreach (var (pattern, label) in Patterns)
        {
            foreach (Match match in pattern.Matches(context.Content))
            {
                var line = GetLineNumber(context.Content, match.Index);
                yield return new Finding(
                    RuleId: "RSH-SEC-001",
                    Title: $"Hardcoded {label} detected",
                    Severity: Severity.Critical,
                    File: context.RelativePath,
                    Line: line,
                    Why: "Hardcoded credentials in source files are frequently committed to version control and exposed in build artifacts. AI assistants commonly generate placeholder secrets that developers forget to replace.",
                    Fix: "Move this secret to an environment variable, user secrets (dotnet user-secrets), or a secrets manager. Never commit credentials to source control."
                );
            }
        }
    }

    private static int GetLineNumber(string content, int charIndex)
    {
        var line = 1;
        for (var i = 0; i < charIndex && i < content.Length; i++)
            if (content[i] == '\n') line++;
        return line;
    }
}
