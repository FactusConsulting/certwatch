using System.Text.Json.Serialization;

namespace CertWatch;

public enum Severity { Ok, Warning, Critical, Error }

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = new[] { typeof(JsonStringEnumConverter<Severity>) })]
[JsonSerializable(typeof(CertResult))]
[JsonSerializable(typeof(CertReport))]
[JsonSerializable(typeof(ErrorResult))]
public partial class JsonContext : JsonSerializerContext { }

public record CertResult(
    string Host,
    int Port,
    bool Ok,
    Severity Severity,
    string? Subject,
    string? Issuer,
    string? SerialNumber,
    string? Thumbprint,
    DateTime? NotBefore,
    DateTime? NotAfter,
    int? DaysRemaining,
    string[] SubjectAltNames,
    string? SignatureAlgorithm,
    string? KeyAlgorithm,
    int? KeySizeBits,
    string? Error);

public record CertReport(
    int Total,
    int Ok,
    int Warning,
    int Critical,
    int Errors,
    CertResult[] Results);

public record ErrorResult(string Error, string? Hint);
