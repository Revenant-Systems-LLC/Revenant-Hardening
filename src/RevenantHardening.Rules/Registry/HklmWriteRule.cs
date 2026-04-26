using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RevenantHardening.Core;
using RevenantHardening.Core.Models;

namespace RevenantHardening.Rules.Registry;

/// <summary>RSH-REG-001: HKLM or HKCR write detected.</summary>
public sealed class HklmWriteRule : IRule
{
    public RuleMetadata Metadata { get; } = new(
        Id: "RSH-REG-001",
        Title: "HKLM/HKCR registry access detected",
        DefaultSeverity: Severity.High,
        FileExtensions: [".cs"]
    );

    public IEnumerable<Finding> Analyze(FileContext context)
    {
        var tree = CSharpSyntaxTree.ParseText(context.Content);
        var root = tree.GetRoot();

        foreach (var access in root.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            var propName = access.Name.Identifier.Text;
            if (propName is not ("LocalMachine" or "ClassesRoot"))
                continue;

            if (access.Expression is not IdentifierNameSyntax { Identifier.Text: "Registry" })
                continue;

            var line = access.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

            yield return new Finding(
                RuleId: "RSH-REG-001",
                Title: $"Registry.{propName} (HKLM/HKCR) access detected",
                Severity: Severity.High,
                File: context.RelativePath,
                Line: line,
                Why: "Writing to HKLM or HKCR requires elevation. On standard user accounts this will fail or throw, and AI-generated code often does this without any error handling or elevation check.",
                Fix: "Move state to HKCU (HKEY_CURRENT_USER) where possible. If HKLM is required, add an explicit elevation check or use a UAC-aware installer to perform the write at install time."
            );
        }
    }
}
