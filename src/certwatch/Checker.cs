using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertWatch;

public static class Checker
{
    public static async Task<CertResult> CheckAsync(
        string host, int port, int warnDays, int critDays, TimeSpan timeout, CancellationToken ct)
    {
        var target = ParseTarget(host, port);
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await tcp.ConnectAsync(target.Host, target.Port, cts.Token);

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.Host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
            }, cts.Token);

            var cert = ssl.RemoteCertificate as X509Certificate2;
            if (cert == null)
                return ErrorResult(target.Host, target.Port, "no remote certificate");

            var now = DateTime.UtcNow;
            var notAfter = cert.NotAfter.ToUniversalTime();
            var notBefore = cert.NotBefore.ToUniversalTime();
            var days = (int)Math.Floor((notAfter - now).TotalDays);

            var severity = CalculateSeverity(days, warnDays, critDays);

            var sans = ExtractSans(cert);
            var keyAlg = GetKeyAlgorithm(cert);
            var keySize = GetKeySize(cert);

            return new CertResult(
                target.Host, target.Port, severity != Severity.Critical, severity,
                cert.Subject, cert.Issuer, cert.SerialNumber, cert.Thumbprint,
                notBefore, notAfter, days, sans,
                cert.SignatureAlgorithm.FriendlyName, keyAlg, keySize, null);
        }
        catch (Exception ex)
        {
            return ErrorResult(target.Host, target.Port, ex.Message);
        }
    }

    internal static (string Host, int Port) ParseTarget(string raw, int defaultPort)
    {
        var trimmed = raw.Replace("https://", "", StringComparison.OrdinalIgnoreCase).TrimEnd('/');
        var slash = trimmed.IndexOf('/');
        if (slash >= 0) trimmed = trimmed[..slash];
        var colon = trimmed.LastIndexOf(':');
        if (colon > 0 && int.TryParse(trimmed[(colon + 1)..], out var p))
            return (trimmed[..colon], p);
        return (trimmed, defaultPort);
    }

    private static string[] ExtractSans(X509Certificate2 cert)
    {
        try
        {
            var ext = cert.Extensions["2.5.29.17"];
            if (ext == null) return Array.Empty<string>();
            var raw = ext.Format(true);
            return raw.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    private static string? GetKeyAlgorithm(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return "RSA";
            using var ec = cert.GetECDsaPublicKey();
            if (ec != null) return "ECDSA";
        }
        catch { }
        return cert.PublicKey.Oid.FriendlyName;
    }

    private static int? GetKeySize(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return rsa.KeySize;
            using var ec = cert.GetECDsaPublicKey();
            if (ec != null) return ec.KeySize;
        }
        catch { }
        return null;
    }

    internal static Severity CalculateSeverity(int daysRemaining, int warnDays, int critDays)
    {
        if (daysRemaining < 0) return Severity.Critical;
        if (daysRemaining <= critDays) return Severity.Critical;
        if (daysRemaining <= warnDays) return Severity.Warning;
        return Severity.Ok;
    }

    private static CertResult ErrorResult(string host, int port, string error) =>
        new(host, port, false, Severity.Error, null, null, null, null, null, null, null,
            Array.Empty<string>(), null, null, null, error);
}
