using RevenantHardening.Core.Models;
using RevenantHardening.Rules.Secrets;
using Xunit;

namespace RevenantHardening.Tests.Rules;

public class SecretsRulesTests
{
    // RSH-SEC-001

    [Fact]
    public void ApiKeyPatternRule_Triggers_OnOpenAiKey()
    {
        var rule = new ApiKeyPatternRule();
        var ctx = Json("""{ "apiKey": "sk-abcdefghijklmnopqrstuvwxyz12345678901234" }""");

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-001", f.RuleId));
        Assert.Equal(Severity.Critical, findings[0].Severity);
    }

    [Fact]
    public void ApiKeyPatternRule_Triggers_OnGithubPat()
    {
        var rule = new ApiKeyPatternRule();
        var ctx = Json("""{ "token": "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG12345678" }""");

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-001", f.RuleId));
    }

    [Fact]
    public void ApiKeyPatternRule_Triggers_OnAwsKey()
    {
        var rule = new ApiKeyPatternRule();
        var ctx = Json("""{ "key": "AKIAIOSFODNN7EXAMPLE" }""");

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-001", f.RuleId));
    }

    [Fact]
    public void ApiKeyPatternRule_DoesNotTrigger_OnShortValues()
    {
        var rule = new ApiKeyPatternRule();
        var ctx = Json("""{ "name": "CursedApp" }""");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-SEC-002

    [Fact]
    public void ResourceSecretRule_Triggers_OnConnectionStringWithPassword()
    {
        var rule = new ResourceSecretRule();
        var ctx = ConfigJson(
            """{ "ConnectionStrings": { "Default": "Server=db;Password=SuperSecret123" } }""");

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-002", f.RuleId));
    }

    [Fact]
    public void ResourceSecretRule_Triggers_OnPasswordField()
    {
        var rule = new ResourceSecretRule();
        var ctx = ConfigJson("""{ "Database": { "Password": "hunter2secret" } }""");

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-002", f.RuleId));
    }

    [Fact]
    public void ResourceSecretRule_DoesNotTrigger_OnInnocuousJson()
    {
        var rule = new ResourceSecretRule();
        var ctx = ConfigJson("""{ "AppName": "MyApp", "Version": "1.0" }""");

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-SEC-003

    [Fact]
    public void ProjectMetadataSecretRule_Triggers_OnGithubPatInCsproj()
    {
        var rule = new ProjectMetadataSecretRule();
        var ctx = Csproj("""
            <PropertyGroup>
              <DeployToken>ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGG12345678</DeployToken>
            </PropertyGroup>
            """);

        var findings = rule.Analyze(ctx).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("RSH-SEC-003", f.RuleId));
    }

    [Fact]
    public void ProjectMetadataSecretRule_DoesNotTrigger_OnNormalProperties()
    {
        var rule = new ProjectMetadataSecretRule();
        var ctx = Csproj("""
            <PropertyGroup>
              <Version>1.0.0</Version>
              <Authors>David Fisher</Authors>
            </PropertyGroup>
            """);

        Assert.Empty(rule.Analyze(ctx));
    }

    // RSH-SEC-004

    [Fact]
    public void ConnectionStringInCodeRule_Triggers_OnAdoNetConnStr()
    {
        var rule = new ConnectionStringInCodeRule();
        var ctx = Cs("string conn = \"Server=prod;Initial Catalog=mydb;User Id=sa;Password=S3cr3t!\";");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-SEC-004", findings[0].RuleId);
        Assert.Equal(Severity.Critical, findings[0].Severity);
    }

    [Fact]
    public void ConnectionStringInCodeRule_Triggers_OnMongoUri()
    {
        var rule = new ConnectionStringInCodeRule();
        var ctx = Cs("var uri = \"mongodb://admin:hunter2secret@mongo.internal:27017\";");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-SEC-004", findings[0].RuleId);
    }

    [Fact]
    public void ConnectionStringInCodeRule_Triggers_OnPostgresUri()
    {
        var rule = new ConnectionStringInCodeRule();
        var ctx = Cs("var uri = \"postgres://user:hunter2@db.internal/mydb\";");

        var findings = rule.Analyze(ctx).ToList();
        Assert.Single(findings);
        Assert.Equal("RSH-SEC-004", findings[0].RuleId);
    }

    [Fact]
    public void ConnectionStringInCodeRule_DoesNotTrigger_OnConnStrWithoutPassword()
    {
        var rule = new ConnectionStringInCodeRule();
        var ctx = Cs("string conn = \"Server=mydb;Database=myapp;Integrated Security=true;\";");

        Assert.Empty(rule.Analyze(ctx));
    }

    [Fact]
    public void ConnectionStringInCodeRule_DoesNotTrigger_OnConfigReference()
    {
        var rule = new ConnectionStringInCodeRule();
        var ctx = Cs("var conn = config.GetConnectionString(\"Default\");");

        Assert.Empty(rule.Analyze(ctx));
    }

    private static FileContext Json(string content) =>
        new("config.json", "config.json", content);

    private static FileContext ConfigJson(string content) =>
        new("appsettings.json", "appsettings.json", content);

    private static FileContext Csproj(string propsXml) =>
        new("App.csproj", "App.csproj",
            $"<Project Sdk=\"Microsoft.NET.Sdk\">{propsXml}</Project>");

    private static FileContext Cs(string code) =>
        new("App.cs", "App.cs", code);
}
