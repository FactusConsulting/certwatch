using System.ComponentModel;
using System.Threading;
using Spectre.Console.Cli;

namespace CertWatch;

public class GlobalSettings : CommandSettings
{
    [CommandOption("--json")]
    [Description("Emit machine-readable JSON to stdout.")]
    public bool Json { get; init; }

    [CommandOption("--prometheus")]
    [Description("Emit Prometheus exposition format (use with node_exporter textfile or pushgateway).")]
    public bool Prometheus { get; init; }

    [CommandOption("--github-actions")]
    [Description("Emit GitHub Actions workflow annotations (::warning::, ::error::).")]
    public bool GitHubActions { get; init; }

    [CommandOption("--quiet")]
    [Description("One status line per host.")]
    public bool Quiet { get; init; }

    [CommandOption("--warn-days <DAYS>")]
    [DefaultValue(30)]
    [Description("Warning threshold in days before expiry.")]
    public int WarnDays { get; init; } = 30;

    [CommandOption("--crit-days <DAYS>")]
    [DefaultValue(7)]
    [Description("Critical threshold in days before expiry. Drives non-zero exit code.")]
    public int CritDays { get; init; } = 7;

    [CommandOption("--timeout <SECONDS>")]
    [DefaultValue(10)]
    [Description("TCP/TLS handshake timeout per host.")]
    public int TimeoutSeconds { get; init; } = 10;

    [CommandOption("--port <PORT>")]
    [DefaultValue(443)]
    [Description("Default port when host doesn't include one.")]
    public int Port { get; init; } = 443;

    [CommandOption("--concurrency <N>")]
    [DefaultValue(8)]
    [Description("Max parallel host checks.")]
    public int Concurrency { get; init; } = 8;

    public TimeSpan Timeout => TimeSpan.FromSeconds(TimeoutSeconds);

    public void ApplyToRender()
    {
        Render.Format = (Json, Prometheus, GitHubActions) switch
        {
            (true, _, _) => OutputFormat.Json,
            (_, true, _) => OutputFormat.Prometheus,
            (_, _, true) => OutputFormat.GitHubActions,
            _ => OutputFormat.Text,
        };
        Render.Quiet = Quiet;
    }
}

public sealed class CheckSettings : GlobalSettings
{
    [CommandArgument(0, "[hosts]")]
    [Description("One or more hosts (e.g. ai-ops.dk factus.dk:443).")]
    public string[] Hosts { get; init; } = Array.Empty<string>();

    [CommandOption("--from-file <PATH>")]
    [Description("Read hosts from file (one per line, # for comments).")]
    public string? FromFile { get; init; }
}

public sealed class CheckCommand : AsyncCommand<CheckSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, CheckSettings s, CancellationToken cancellationToken)
    {
        s.ApplyToRender();

        var hosts = new List<string>(s.Hosts);

        if (!string.IsNullOrEmpty(s.FromFile))
        {
            if (!File.Exists(s.FromFile)) { Render.Error($"file not found: {s.FromFile}"); return 78; }
            AddHostLines(hosts, await File.ReadAllLinesAsync(s.FromFile));
        }

        if (!Console.IsInputRedirected && hosts.Count == 0)
        {
            Render.Error("no hosts provided", "Provide hosts as args, via --from-file, or pipe via stdin.");
            return 78;
        }

        if (Console.IsInputRedirected)
        {
            await AddHostLinesFromStdinAsync(hosts);
        }

        if (hosts.Count == 0) { Render.Error("no hosts to check"); return 78; }

        var results = await CheckAllAsync(hosts, s);
        var report = BuildReport(results);
        Render.Emit(report);
        return ExitCodeFor(report);
    }

    private static void AddHostLines(List<string> hosts, IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            hosts.Add(trimmed);
        }
    }

    private static async Task AddHostLinesFromStdinAsync(List<string> hosts)
    {
        string? line;
        while ((line = await Console.In.ReadLineAsync()) != null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0 && !trimmed.StartsWith('#')) hosts.Add(trimmed);
        }
    }

    private static async Task<CertResult[]> CheckAllAsync(List<string> hosts, CheckSettings s)
    {
        var sem = new SemaphoreSlim(Math.Max(1, s.Concurrency));
        var tasks = hosts.Select(async h =>
        {
            await sem.WaitAsync();
            try { return await Checker.CheckAsync(h, s.Port, s.WarnDays, s.CritDays, s.Timeout, default); }
            finally { sem.Release(); }
        });
        return await Task.WhenAll(tasks);
    }

    private static CertReport BuildReport(CertResult[] results)
    {
        var ok = results.Count(r => r.Severity == Severity.Ok);
        var warn = results.Count(r => r.Severity == Severity.Warning);
        var crit = results.Count(r => r.Severity == Severity.Critical);
        var err = results.Count(r => r.Severity == Severity.Error);
        return new CertReport(results.Length, ok, warn, crit, err, results);
    }

    private static int ExitCodeFor(CertReport report)
    {
        if (report.Critical > 0) return 2;
        if (report.Warning > 0) return 1;
        if (report.Errors > 0) return 74;
        return 0;
    }
}

public static class AgentGuidance
{
    public const string Text = """
            certwatch — guidance for AI agents

            WHEN TO USE
              Check SSL/TLS certificate expiry across one or many hosts. Use for
              monitoring, scheduled health checks, and pre-flight validation in
              deployment workflows.

            SAFE BY DEFAULT
              Read-only TLS handshake. No state mutation. Does not validate the
              certificate chain — only reports what the server presents. Safe to
              call from a loop or scheduled job.

            EXIT CODES (these double as severity)
              0   all OK
              1   at least one host hit the warning threshold (--warn-days)
              2   at least one host hit critical threshold (--crit-days) or already expired
              74  network/handshake error on at least one host (and no critical)
              78  configuration error (e.g. file not found)

            OUTPUT FORMATS
              --json              stable snake_case JSON
              --prometheus        Prometheus exposition (gauges: days_remaining, check_ok)
              --github-actions    workflow annotations (::warning::, ::error::, ::notice::)
              default             colored table

            INPUT MODES
              certwatch check ai-ops.dk factus.dk           # positional args
              certwatch check --from-file domains.txt       # from file (# = comment)
              cat domains.txt | certwatch check             # from stdin

            EXAMPLES
              certwatch check ai-ops.dk factus.dk --json | jq '.results[] | {host,days:.days_remaining}'
              certwatch check --from-file domains.txt --warn-days 30 --crit-days 7 --prometheus > /var/lib/node_exporter/textfile_collector/certwatch.prom
              certwatch check $(dig +short A factus.dk) --port 443 --github-actions
            """;
}

public sealed class HelpAiCommand : Command
{
    protected override int Execute(CommandContext context, CancellationToken cancellationToken)
    {
        Console.WriteLine(AgentGuidance.Text);
        return 0;
    }
}
