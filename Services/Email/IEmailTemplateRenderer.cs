using Microsoft.Extensions.Configuration;
using System.Text.RegularExpressions;

namespace AuthenticationAPI.Services.Email;

public interface IEmailTemplateRenderer
{
    Task<(string Html, string Text)> RenderAsync(string templateName, IDictionary<string, string> values, CancellationToken ct = default);
}

public sealed class EmailTemplateRenderer : IEmailTemplateRenderer
{
    private readonly IWebHostEnvironment _env;
    private readonly IConfiguration _config;

    public EmailTemplateRenderer(IWebHostEnvironment env, IConfiguration config)
    {
        _env = env;
        _config = config;
    }

    public async Task<(string Html, string Text)> RenderAsync(string templateName, IDictionary<string, string> values, CancellationToken ct = default)
    {
        var basePath = Path.Combine(_env.ContentRootPath, "Email", "Templates");
        var file = Path.Combine(basePath, templateName + ".html");
        if (!File.Exists(file)) throw new FileNotFoundException($"Email template not found: {file}");

        // Branding defaults
        var primary = _config["Email:Brand:PrimaryBlue"] ?? "#0B5FFF";
        var accent = _config["Email:Brand:AccentOrange"] ?? "#FF7A00";
        var alert = _config["Email:Brand:AlertRed"] ?? "#E53935";
        var appName = _config["Email:Brand:AppName"] ?? "BCMTrack";

        var html = await File.ReadAllTextAsync(file, ct);

        // Merge values with defaults
        string GV(string key, string? def = "") => values != null && values.TryGetValue(key, out var v) && v != null ? v : def ?? string.Empty;

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["AppName"] = appName,
            ["PrimaryBlue"] = primary,
            ["AccentOrange"] = accent,
            ["AlertRed"] = alert,
            ["Title"] = GV("Title", appName),
            ["Intro"] = GV("Intro", string.Empty),
            ["ActionText"] = GV("ActionText", string.Empty),
            ["ActionUrl"] = GV("ActionUrl", string.Empty),
            ["Token"] = GV("Token", string.Empty),
            ["Footer"] = GV("Footer", $"This email was sent by {appName}. If you did not request this, you can safely ignore it.")
        };

        foreach (var kv in values)
        {
            map[kv.Key] = kv.Value ?? string.Empty;
        }

        foreach (var kv in map)
        {
            html = html.Replace("{{" + kv.Key + "}}", kv.Value, StringComparison.OrdinalIgnoreCase);
        }
        // Handle very simple conditional: {{#if Token}} ... {{/if}}
        if (string.IsNullOrWhiteSpace(map.GetValueOrDefault("Token")))
        {
            html = Regex.Replace(html, "\\{\\{#if Token\\}\\}[\\s\\S]*?\\{\\{\\/if\\}\\}", string.Empty, RegexOptions.IgnoreCase);
        }

        // Light text fallback
        var text = BuildTextFallback(map);
        return (html, text);
    }

    private static string BuildTextFallback(IDictionary<string, string> v)
    {
        var sb = new System.Text.StringBuilder();
        void line(string? s){ if (!string.IsNullOrWhiteSpace(s)) sb.AppendLine(s); }
        string? title = v.ContainsKey("Title") ? v["Title"] : null;
        string? intro = v.ContainsKey("Intro") ? v["Intro"] : null;
        string? url = v.ContainsKey("ActionUrl") ? v["ActionUrl"] : null;
        string? token = v.ContainsKey("Token") ? v["Token"] : null;
        string? footer = v.ContainsKey("Footer") ? v["Footer"] : null;
        line(title);
        line(intro);
        if (!string.IsNullOrWhiteSpace(url))
        {
            line("Link: " + url);
        }
        if (!string.IsNullOrWhiteSpace(token))
        {
            line("Token: " + token);
        }
        line("");
        line(footer);
        return sb.ToString();
    }
}
