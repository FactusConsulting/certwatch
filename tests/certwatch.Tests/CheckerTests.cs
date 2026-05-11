using Xunit;

namespace CertWatch.Tests;

public class ParseTargetTests
{
    [Theory]
    [InlineData("ai-ops.dk", "ai-ops.dk", 443)]
    [InlineData("factus.dk", "factus.dk", 443)]
    [InlineData("example.com", "example.com", 443)]
    public void ParseTarget_DefaultsPort_WhenMissing(string input, string expectedHost, int expectedPort)
    {
        var (host, port) = Checker.ParseTarget(input, 443);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("nas.factus.dk:9001", "nas.factus.dk", 9001)]
    [InlineData("smtp.example.com:587", "smtp.example.com", 587)]
    [InlineData("ldap.corp:636", "ldap.corp", 636)]
    public void ParseTarget_ExtractsExplicitPort(string input, string expectedHost, int expectedPort)
    {
        var (host, port) = Checker.ParseTarget(input, 443);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("https://ai-ops.dk", "ai-ops.dk", 443)]
    [InlineData("HTTPS://factus.dk", "factus.dk", 443)]
    [InlineData("https://nas.factus.dk:9001", "nas.factus.dk", 9001)]
    public void ParseTarget_StripsHttpsScheme(string input, string expectedHost, int expectedPort)
    {
        var (host, port) = Checker.ParseTarget(input, 443);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("https://example.com/path", "example.com", 443)]
    [InlineData("https://example.com/some/long/path", "example.com", 443)]
    [InlineData("example.com/path", "example.com", 443)]
    public void ParseTarget_StripsPath(string input, string expectedHost, int expectedPort)
    {
        var (host, port) = Checker.ParseTarget(input, 443);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Fact]
    public void ParseTarget_CustomDefaultPort_IsRespected()
    {
        var (host, port) = Checker.ParseTarget("ldap.example.com", 636);
        Assert.Equal("ldap.example.com", host);
        Assert.Equal(636, port);
    }
}

public class CalculateSeverityTests
{
    [Theory]
    [InlineData(100, 30, 7, Severity.Ok)]
    [InlineData(60, 30, 7, Severity.Ok)]
    [InlineData(31, 30, 7, Severity.Ok)]
    public void Above_WarnThreshold_IsOk(int days, int warn, int crit, Severity expected)
    {
        Assert.Equal(expected, Checker.CalculateSeverity(days, warn, crit));
    }

    [Theory]
    [InlineData(30, 30, 7, Severity.Warning)]
    [InlineData(15, 30, 7, Severity.Warning)]
    [InlineData(8, 30, 7, Severity.Warning)]
    public void Between_WarnAndCrit_IsWarning(int days, int warn, int crit, Severity expected)
    {
        Assert.Equal(expected, Checker.CalculateSeverity(days, warn, crit));
    }

    [Theory]
    [InlineData(7, 30, 7, Severity.Critical)]
    [InlineData(3, 30, 7, Severity.Critical)]
    [InlineData(0, 30, 7, Severity.Critical)]
    public void At_Or_Below_CritThreshold_IsCritical(int days, int warn, int crit, Severity expected)
    {
        Assert.Equal(expected, Checker.CalculateSeverity(days, warn, crit));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-30)]
    [InlineData(-100)]
    public void Negative_DaysRemaining_IsCritical(int days)
    {
        Assert.Equal(Severity.Critical, Checker.CalculateSeverity(days, 30, 7));
    }

    [Fact]
    public void CustomThresholds_AreRespected()
    {
        Assert.Equal(Severity.Warning, Checker.CalculateSeverity(45, 60, 14));
        Assert.Equal(Severity.Critical, Checker.CalculateSeverity(10, 60, 14));
        Assert.Equal(Severity.Ok, Checker.CalculateSeverity(70, 60, 14));
    }
}
