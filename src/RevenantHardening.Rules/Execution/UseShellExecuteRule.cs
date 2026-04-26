using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RevenantHardening.Core;
using RevenantHardening.Core.Models;

namespace RevenantHardening.Rules.Execution;

/// <summary>RSH-EXEC-002: UseShellExecute = true in a ProcessStartInfo.</summary>
public sealed class UseShellExecuteRule : IRule
{
    public RuleMetadata Metadata { get; } = new(
        Id: "RSH-EXEC-002",
        Title: "UseShellExecute = true in risky context",
        DefaultSeverity: Severity.Medium,
        FileExtensions: [".cs"]
    );

    public IEnumerable<Finding> Analyze(FileContext context)
    {
        var tree = CSharpSyntaxTree.ParseText(context.Content);
        var root = tree.GetRoot();

        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            var left = assignment.Left;
            string? propName = left switch
            {
                MemberAccessExpressionSyntax m => m.Name.Identifier.Text,
                IdentifierNameSyntax id => id.Identifier.Text,
                _ => null
            };

            if (propName != "UseShellExecute")
                continue;

            if (assignment.Right is not LiteralExpressionSyntax lit)
                continue;

            if (lit.Token.ValueText is not ("True" or "true"))
                continue;

            var line = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

            yield return new Finding(
                RuleId: "RSH-EXEC-002",
                Title: "UseShellExecute = true detected",
                Severity: Severity.Medium,
                File: context.RelativePath,
                Line: line,
                Why: "UseShellExecute = true passes the executable to the Windows shell for launch, enabling shell injection if any argument is derived from user input. AI-generated code commonly sets this without considering the risk.",
                Fix: "Set UseShellExecute = false and specify the executable path directly. Ensure all arguments are validated or come from trusted sources only."
            );
        }
    }
}
