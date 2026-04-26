using RevenantHardening.Core;
using RevenantHardening.Rules;
using Xunit;

namespace RevenantHardening.Tests.Integration;

public class ScanIntegrationTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "fixtures", "CursedApp");

    [Fact]
    public void Scan_CursedApp_ReturnsFindings()
    {
        Assert.True(Directory.Exists(FixturePath), $"Fixture missing: {FixturePath}");

        var options = ScanOptions.Default(FixturePath);
        var result = RuleEngine.Scan(RuleRegistry.All, options);

        Assert.True(result.FilesScanned > 0, "No files were scanned");
        Assert.NotEmpty(result.Findings);
    }

    [Fact]
    public void Scan_CursedApp_GetsGradeF()
    {
        var options = ScanOptions.Default(FixturePath);
        var result = RuleEngine.Scan(RuleRegistry.All, options);

        Assert.Equal('F', result.Grade);
    }

    [Theory]
    [InlineData("RSH-MSIX-001")]
    [InlineData("RSH-MSIX-002")]
    [InlineData("RSH-MSIX-003")]
    [InlineData("RSH-REG-001")]
    [InlineData("RSH-REG-002")]
    [InlineData("RSH-REG-003")]
    [InlineData("RSH-EXEC-001")]
    [InlineData("RSH-EXEC-002")]
    [InlineData("RSH-EXEC-003")]
    [InlineData("RSH-EXEC-004")]
    [InlineData("RSH-EXEC-005")]
    [InlineData("RSH-REG-004")]
    [InlineData("RSH-SEC-001")]
    [InlineData("RSH-SEC-002")]
    [InlineData("RSH-SEC-003")]
    [InlineData("RSH-SEC-004")]
    [InlineData("RSH-MSIX-004")]
    [InlineData("RSH-XAML-001")]
    [InlineData("RSH-XAML-002")]
    [InlineData("RSH-XAML-003")]
    [InlineData("RSH-PINVOKE-001")]
    [InlineData("RSH-PINVOKE-002")]
    [InlineData("RSH-PINVOKE-003")]
    [InlineData("RSH-ACL-001")]
    [InlineData("RSH-ACL-002")]
    public void Scan_CursedApp_FindsExpectedRuleId(string expectedRuleId)
    {
        var options = ScanOptions.Default(FixturePath);
        var result = RuleEngine.Scan(RuleRegistry.All, options);

        var ruleIds = result.Findings.Select(f => f.RuleId).ToHashSet();
        Assert.Contains(expectedRuleId, ruleIds);
    }

    [Fact]
    public void Scan_EmptyDirectory_ReturnsCleanResult()
    {
        var empty = Path.Combine(Path.GetTempPath(), $"rsh-empty-{Guid.NewGuid()}");
        Directory.CreateDirectory(empty);
        try
        {
            var options = ScanOptions.Default(empty);
            var result = RuleEngine.Scan(RuleRegistry.All, options);

            Assert.Empty(result.Findings);
            Assert.Equal(100, result.Score);
            Assert.Equal('A', result.Grade);
        }
        finally
        {
            Directory.Delete(empty, recursive: true);
        }
    }
}
