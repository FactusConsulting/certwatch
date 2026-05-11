using System.Globalization;
using System.Text;
using System.Text.Json;
using Spectre.Console;

namespace CertWatch;

public enum OutputFormat { Text, Json, Prometheus, GitHubActions }

public static class Render
{
    public static OutputFormat Format { get; set; } = OutputFormat.Text;
    public static bool Quiet { get; set; } = false;

    public static void Emit(CertReport rep)
    {
        switch (Format)
        {
            case OutputFormat.Json:
                Console.WriteLine(JsonSerializer.Serialize(rep, JsonContext.Default.CertReport));
                return;
            case OutputFormat.Prometheus:
                EmitPrometheus(rep);
                return;
            case OutputFormat.GitHubActions:
                EmitGitHubActions(rep);
                return;
            default:
                EmitText(rep);
                return;
        }
    }

    private static void EmitText(CertReport rep)
    {
        if (Quiet)
        {
            foreach (var r in rep.Results)
                Console.WriteLine($"{SeverityLabel(r.Severity).ToLowerInvariant()} {r.Host}:{r.Port} {r.DaysRemaining?.ToString() ?? "-"}d");
            return;
        }
        var t = new Table().Border(TableBorder.Rounded);
        t.AddColumn("Status").AddColumn("Host").AddColumn("Expires").AddColumn(new TableColumn("Days").RightAligned()).AddColumn("Issuer");
        foreach (var r in rep.Results)
        {
            var status = r.Severity switch
            {
                Severity.Ok => "[green]✓ OK[/]",
                Severity.Warning => "[yellow]⚠ WARN[/]",
                Severity.Critical => "[red]✗ CRIT[/]",
                _ => "[red]✗ ERR[/]"
            };
            var hostStr = $"{r.Host}:{r.Port}";
            var expires = r.NotAfter?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
            var days = r.DaysRemaining?.ToString() ?? "—";
            var issuer = r.Error != null ? $"[red]{Markup.Escape(Truncate(r.Error, 40))}[/]" :
                Markup.Escape(ExtractCN(r.Issuer ?? "—"));
            t.AddRow(status, Markup.Escape(hostStr), expires, days, issuer);
        }
        AnsiConsole.Write(t);
        AnsiConsole.MarkupLine(
            $"[grey]Total {rep.Total} · [/][green]{rep.Ok} ok[/][grey] · [/][yellow]{rep.Warning} warning[/][grey] · [/][red]{rep.Critical} critical[/][grey] · [/][red]{rep.Errors} error[/]");
    }

    private static void EmitPrometheus(CertReport rep)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# HELP certwatch_days_remaining Days until certificate expiry");
        sb.AppendLine("# TYPE certwatch_days_remaining gauge");
        foreach (var r in rep.Results)
        {
            if (r.DaysRemaining.HasValue)
                sb.AppendLine($"certwatch_days_remaining{{host=\"{Escape(r.Host)}\",port=\"{r.Port}\"}} {r.DaysRemaining.Value}");
        }
        sb.AppendLine("# HELP certwatch_check_ok 1 if certificate is reachable and parseable");
        sb.AppendLine("# TYPE certwatch_check_ok gauge");
        foreach (var r in rep.Results)
        {
            var ok = r.Error == null ? 1 : 0;
            sb.AppendLine($"certwatch_check_ok{{host=\"{Escape(r.Host)}\",port=\"{r.Port}\"}} {ok}");
        }
        Console.Write(sb);
    }

    private static void EmitGitHubActions(CertReport rep)
    {
        foreach (var r in rep.Results)
        {
            var host = $"{r.Host}:{r.Port}";
            switch (r.Severity)
            {
                case Severity.Warning:
                    Console.WriteLine($"::warning title=Certificate expiring soon::{host} expires in {r.DaysRemaining} days");
                    break;
                case Severity.Critical:
                    Console.WriteLine($"::error title=Certificate critical::{host} expires in {r.DaysRemaining} days");
                    break;
                case Severity.Error:
                    Console.WriteLine($"::error title=Certificate check failed::{host}: {r.Error}");
                    break;
                default:
                    Console.WriteLine($"::notice title=Certificate ok::{host} expires in {r.DaysRemaining} days");
                    break;
            }
        }
        Console.WriteLine($"::notice title=Summary::Total {rep.Total} — {rep.Ok} ok, {rep.Warning} warning, {rep.Critical} critical, {rep.Errors} error");
    }

    public static void Error(string err, string? hint = null)
    {
        if (Format == OutputFormat.Json)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new ErrorResult(err, hint), JsonContext.Default.ErrorResult));
            return;
        }
        AnsiConsole.MarkupLine($"[red]error:[/] {err}");
        if (hint != null) AnsiConsole.MarkupLine($"[grey]hint:[/]  {hint}");
    }

    public static string SeverityLabel(Severity s) => s switch
    {
        Severity.Ok => "OK",
        Severity.Warning => "WARNING",
        Severity.Critical => "CRITICAL",
        _ => "ERROR"
    };

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    private static string Truncate(string s, int n) => s.Length > n ? s[..(n - 1)] + "…" : s;

    private static string ExtractCN(string dn)
    {
        var cn = dn.Split(',').FirstOrDefault(s => s.TrimStart().StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
        return cn?.Trim()[3..] ?? dn;
    }
}
