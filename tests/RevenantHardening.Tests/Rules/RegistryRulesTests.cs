using RevenantHardening.Core.Models;
using RevenantHardening.Rules.Registry;
using Xunit;

namespace RevenantHardening.Tests.Rules;

public class RegistryRulesTests
{
    // RSH-REG-001

    [Fact]
    public void HklmWriteRule_Triggers_OnLocalMachineSetValue()
    {
        var rule = new HklmWriteRule();
        var ctx = Cs("Registry.LocalMachine.OpenSubKey(\"SOFTWARE\\\\MyApp\", true).SetValue(\"k\", \"v\");");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-REG-001", findings[0].RuleId);
    }

    [Fact]
    public void HklmWriteRule_Triggers_OnClassesRootCreateSubKey()
    {
        var rule = new HklmWriteRule();
        var ctx = Cs("Registry.ClassesRoot.CreateSubKey(\"myapp\");");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-REG-001", findings[0].RuleId);
    }

    [Fact]
    public void HklmWriteRule_Triggers_OnTwoStepWrite()
    {
        var rule = new HklmWriteRule();
        var ctx = Cs("""
            void Write()
            {
                var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\MyApp", true);
                key?.SetValue("x", "y");
            }
            """);

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-REG-001", f.RuleId));
    }

    [Fact]
    public void HklmWriteRule_DoesNotTrigger_OnHklmRead()
    {
        var rule = new HklmWriteRule();
        var ctx = Cs("var key = Registry.LocalMachine.OpenSubKey(\"SOFTWARE\\\\MyApp\");");

        Assert.Empty(rule.Analyze(ctx));
    }

    [Fact]
    public void HklmWriteRule_DoesNotTrigger_OnCurrentUser()
    {
        var rule = new HklmWriteRule();
        var ctx = Cs("Registry.CurrentUser.OpenSubKey(\"SOFTWARE\\\\MyApp\", true).SetValue(\"k\", \"v\");");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-REG-002

    [Fact]
    public void WritableHandleRule_Triggers_OnNamedWritableArg()
    {
        var rule = new WritableHandleRule();
        var ctx = Cs("var key = Registry.LocalMachine.OpenSubKey(\"SOFTWARE\\\\MyApp\", writable: true);");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-REG-002", findings[0].RuleId);
    }

    [Fact]
    public void WritableHandleRule_Triggers_OnPositionalTrueArg()
    {
        var rule = new WritableHandleRule();
        var ctx = Cs("var key = Registry.LocalMachine.OpenSubKey(\"SOFTWARE\\\\MyApp\", true);");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-REG-002", findings[0].RuleId);
    }

    [Fact]
    public void WritableHandleRule_DoesNotTrigger_OnReadOnly()
    {
        var rule = new WritableHandleRule();
        var ctx = Cs("var key = Registry.LocalMachine.OpenSubKey(\"SOFTWARE\\\\MyApp\", false);");

        Assert.Empty(rule.Analyze(ctx));
    }

    [Fact]
    public void WritableHandleRule_DoesNotTrigger_OnCurrentUserWritable()
    {
        var rule = new WritableHandleRule();
        var ctx = Cs("var key = Registry.CurrentUser.OpenSubKey(\"SOFTWARE\\\\MyApp\", true);");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-REG-003

    [Fact]
    public void ElevationGuardRule_Triggers_WithoutGuard()
    {
        var rule = new ElevationGuardRule();
        var ctx = Cs("""
            void DoWrite()
            {
                var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\MyApp", true);
                key?.SetValue("x", "y");
            }
            """);

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-REG-003", findings[0].RuleId);
    }

    [Fact]
    public void ElevationGuardRule_DoesNotTrigger_WithElevationGuard()
    {
        var rule = new ElevationGuardRule();
        var ctx = Cs("""
            void DoWrite()
            {
                var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator)) return;
                var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\MyApp", true);
                key?.SetValue("x", "y");
            }
            """);

        Assert.Empty(rule.Analyze(ctx));
    }

    private static FileContext Cs(string code) =>
        new FileContext("test.cs", "test.cs", $"using Microsoft.Win32;\n{code}");
}
