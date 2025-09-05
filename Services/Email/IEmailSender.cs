namespace AuthenticationAPI.Services.Email;

public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken ct = default);
}

public sealed class ConsoleEmailSender : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        Console.WriteLine($"[EMAIL] To={to} Subject={subject}\n{body}");
        return Task.CompletedTask;
    }
}
