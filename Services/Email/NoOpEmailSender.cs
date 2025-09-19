namespace AuthenticationAPI.Services.Email;

public class NoOpEmailSender : IEmailSender
{
    public void QueueSendAsync(string to, string subject, string body)
    {
        // No-op implementation for testing/development environments without SMTP
        // This allows the application to run without requiring SMTP configuration
    }
}