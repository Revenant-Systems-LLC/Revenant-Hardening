using System.Xml.Linq;
using RevenantHardening.Core;
using RevenantHardening.Core.Models;

namespace RevenantHardening.Rules.Msix;

/// <summary>RSH-MSIX-002: runFullTrust capability enabled.</summary>
public sealed class RunFullTrustRule : IRule
{
    public RuleMetadata Metadata { get; } = new(
        Id: "RSH-MSIX-002",
        Title: "runFullTrust capability enabled",
        DefaultSeverity: Severity.High,
        FileExtensions: [".appxmanifest"]
    );

    public IEnumerable<Finding> Analyze(FileContext context)
    {
        XDocument doc;
        try { doc = XDocument.Parse(context.Content); }
        catch { yield break; }

        foreach (var element in doc.Descendants())
        {
            if (element.Name.LocalName != "Capability")
                continue;

            var name = element.Attribute("Name")?.Value;
            if (!string.Equals(name, "runFullTrust", StringComparison.OrdinalIgnoreCase))
                continue;

            yield return new Finding(
                RuleId: "RSH-MSIX-002",
                Title: "runFullTrust capability is enabled",
                Severity: Severity.High,
                File: context.RelativePath,
                Line: null,
                Why: "runFullTrust bypasses the MSIX sandbox and grants the app the same privileges as the installing user. This is often unnecessary for desktop utilities and is a common AI-generated manifest mistake.",
                Fix: "Remove runFullTrust unless your app genuinely requires full-trust execution. Prefer sandboxed capabilities where possible."
            );
        }
    }
}
