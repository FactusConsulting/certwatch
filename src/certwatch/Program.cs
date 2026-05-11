using System.Reflection;
using CertWatch;
using Spectre.Console.Cli;

// --help-ai as a global flag, in addition to the help-ai subcommand —
// matches the convention from the ai-ops.dk blog post on agent-friendly CLIs.
if (args.Any(a => a == "--help-ai"))
{
    Console.WriteLine(AgentGuidance.Text);
    return 0;
}

var version = Assembly.GetExecutingAssembly()
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
    ?.InformationalVersion ?? "0.0.0-dev";

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("certwatch");
    config.SetApplicationVersion(version);
    config.AddCommand<CheckCommand>("check")
        .WithDescription("Check certificate expiry on one or more hosts.")
        .WithExample("check", "ai-ops.dk", "factus.dk")
        .WithExample("check", "--from-file", "domains.txt", "--warn-days", "30", "--json")
        .WithExample("check", "ai-ops.dk", "--prometheus")
        .WithExample("check", "ai-ops.dk", "--github-actions");
    config.AddCommand<HelpAiCommand>("help-ai")
        .WithDescription("Print guidance specifically for AI agents invoking this tool.");
});
return await app.RunAsync(args);
