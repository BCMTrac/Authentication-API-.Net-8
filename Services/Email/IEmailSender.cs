namespace AuthenticationAPI.Services.Email;

public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken ct = default);
}

public sealed class ConsoleEmailSender : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
    // Print in a single line so tokens are easy to copy from the terminal
    Console.WriteLine($"[EMAIL] To={to} Subject={subject} {body}");
        return Task.CompletedTask;
    }
}
