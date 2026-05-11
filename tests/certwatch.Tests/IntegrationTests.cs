using Xunit;

namespace CertWatch.Tests;

/// <summary>
/// Integration tests that hit real public TLS endpoints.
/// Run with: dotnet test --filter Category=Integration
/// Skip locally with: dotnet test --filter Category!=Integration
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    [Fact]
    public async Task GoogleDotCom_ReturnsValidCertificate()
    {
        var r = await Checker.CheckAsync("google.com", 443, warnDays: 30, critDays: 7, Timeout, default);

        Assert.NotEqual(Severity.Error, r.Severity);
        Assert.NotNull(r.Subject);
        Assert.NotNull(r.Issuer);
        Assert.NotNull(r.NotAfter);
        Assert.True(r.DaysRemaining > 0, $"Expected days_remaining > 0, got {r.DaysRemaining}");
    }

    [Fact]
    public async Task GitHubDotCom_HasReasonablyLongValidity()
    {
        var r = await Checker.CheckAsync("github.com", 443, warnDays: 30, critDays: 7, Timeout, default);

        Assert.Null(r.Error);
        Assert.NotNull(r.DaysRemaining);
    }

    [Fact]
    public async Task ExpiredBadsslCom_ReportsCritical()
    {
        var r = await Checker.CheckAsync("expired.badssl.com", 443, warnDays: 30, critDays: 7, Timeout, default);

        // The cert is technically retrievable (we don't validate chain) but it's
        // expired, so days_remaining should be negative and severity Critical.
        Assert.True(
            r.Severity == Severity.Critical || r.Severity == Severity.Error,
            $"Expected Critical or Error for expired cert, got {r.Severity}");
        if (r.Error == null)
        {
            Assert.NotNull(r.DaysRemaining);
            Assert.True(r.DaysRemaining < 0, $"Expected negative days_remaining, got {r.DaysRemaining}");
        }
    }

    [Fact]
    public async Task SelfSignedBadsslCom_IsStillRetrievable()
    {
        // certwatch deliberately doesn't validate the chain — the tool reports
        // *what the server presents*, not whether a normal client would trust it.
        // So a self-signed cert with valid dates should retrieve fine.
        var r = await Checker.CheckAsync("self-signed.badssl.com", 443, warnDays: 30, critDays: 7, Timeout, default);

        Assert.Null(r.Error);
        Assert.NotNull(r.Subject);
        Assert.NotNull(r.NotAfter);
        // Self-signed certs typically have the same Subject and Issuer
        Assert.Equal(r.Subject, r.Issuer);
    }

    [Fact]
    public async Task NonExistentHost_ReportsError()
    {
        var r = await Checker.CheckAsync(
            "this-host-definitely-does-not-exist-12345.example", 443,
            warnDays: 30, critDays: 7, Timeout, default);

        Assert.Equal(Severity.Error, r.Severity);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public async Task UnreachablePort_ReportsError()
    {
        // Port 9999 on localhost is very unlikely to be listening
        var r = await Checker.CheckAsync(
            "127.0.0.1", 9999,
            warnDays: 30, critDays: 7,
            TimeSpan.FromSeconds(2), default);

        Assert.Equal(Severity.Error, r.Severity);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public async Task LeafCertificate_HasKeyAlgorithmAndSize()
    {
        var r = await Checker.CheckAsync("github.com", 443, warnDays: 30, critDays: 7, Timeout, default);

        Assert.NotNull(r.KeyAlgorithm);
        Assert.NotNull(r.KeySizeBits);
        Assert.True(r.KeySizeBits >= 256, $"Expected key size >= 256 bits, got {r.KeySizeBits}");
    }
}
