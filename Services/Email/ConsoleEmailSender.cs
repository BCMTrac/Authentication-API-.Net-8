using System;

namespace AuthenticationAPI.Services.Email;

public sealed class ConsoleEmailSender : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        var preview = body?.Length > 200 ? body.Substring(0, 200) + "…" : body ?? string.Empty;
        Console.WriteLine($"[EMAIL] to={to} subject={subject} bodyPreview={preview.Replace('\n',' ').Replace('\r',' ')}");
        return Task.CompletedTask;
    }
}

