using RevenantHardening.Core.Models;
using RevenantHardening.Rules.Msix;
using Xunit;

namespace RevenantHardening.Tests.Rules;

public class MsixRulesTests
{
    // RSH-MSIX-001

    [Fact]
    public void MsixCapabilityRule_Triggers_OnBroadFileSystemAccess()
    {
        var rule = new MsixCapabilityRule();
        var ctx = Manifest(@"<Capabilities>
            <rescap:Capability Name=""broadFileSystemAccess"" />
          </Capabilities>");

        var findings = rule.Analyze(ctx).ToList();

        Assert.Single(findings);
        Assert.Equal("RSH-MSIX-001", findings[0].RuleId);
        Assert.Equal(Severity.High, findings[0].Severity);
    }

    [Fact]
    public void MsixCapabilityRule_Triggers_MultipleCapabilities()
    {
        var rule = new MsixCapabilityRule();
        var ctx = Manifest(@"<Capabilities>
            <rescap:Capability Name=""broadFileSystemAccess"" />
            <Capability Name=""internetClientServer"" />
          </Capabilities>");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("RSH-MSIX-001", f.RuleId));
    }

    [Fact]
    public void MsixCapabilityRule_DoesNotTrigger_OnSafeCapabilities()
    {
        var rule = new MsixCapabilityRule();
        var ctx = Manifest(@"<Capabilities>
            <Capability Name=""internetClient"" />
          </Capabilities>");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-MSIX-002

    [Fact]
    public void RunFullTrustRule_Triggers_OnRunFullTrust()
    {
        var rule = new RunFullTrustRule();
        var ctx = Manifest(@"<Capabilities>
            <rescap:Capability Name=""runFullTrust"" />
          </Capabilities>");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-MSIX-002", findings[0].RuleId);
    }

    [Fact]
    public void RunFullTrustRule_DoesNotTrigger_WithoutIt()
    {
        var rule = new RunFullTrustRule();
        var ctx = Manifest(@"<Capabilities>
            <Capability Name=""internetClient"" />
          </Capabilities>");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-MSIX-003

    [Fact]
    public void DebugSigningRule_Triggers_OnTestCert()
    {
        var rule = new DebugSigningRule();
        var ctx = Manifest(@"", publisher: "CN=TestCert");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-MSIX-003", findings[0].RuleId);
    }

    [Fact]
    public void DebugSigningRule_Triggers_OnDebugPublisher()
    {
        var rule = new DebugSigningRule();
        var ctx = Manifest(@"", publisher: "CN=Debug, O=MyOrg");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-MSIX-003", findings[0].RuleId);
    }

    [Fact]
    public void DebugSigningRule_DoesNotTrigger_OnRealPublisher()
    {
        var rule = new DebugSigningRule();
        var ctx = Manifest(@"", publisher: "CN=Revenant Systems, O=RevenantSystems, L=Seattle, S=WA, C=US");

        Assert.Empty(rule.Analyze(ctx));
    }

    private static FileContext Manifest(string capabilitiesXml, string publisher = "CN=TestPublisher") =>
        new FileContext(
            Path: "Package.appxmanifest",
            RelativePath: "Package.appxmanifest",
            Content: $"""
                <?xml version="1.0" encoding="utf-8"?>
                <Package
                  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
                  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
                  <Identity Name="TestApp" Publisher="{publisher}" Version="1.0.0.0" />
                  {capabilitiesXml}
                </Package>
                """
        );
}
