namespace RevenantHardening.Core.Models;

public sealed record RuleMetadata(
    string Id,
    string Title,
    Severity DefaultSeverity,
    string[] FileExtensions
);
