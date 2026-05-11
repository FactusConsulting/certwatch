using CertWatch;
using Spectre.Console.Cli;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("certwatch");
    config.SetApplicationVersion("0.1.0");
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
