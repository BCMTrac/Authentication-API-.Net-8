using System.Net;
using System.Net.Mail;

namespace AuthenticationAPI.Services.Email;

public sealed class SmtpEmailSender : IEmailSender
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _enableSsl;
    private readonly string _username;
    private readonly string _password;
    private readonly string _fromEmail;
    private readonly string _fromName;

    public SmtpEmailSender(
        string host,
        int port,
        bool enableSsl,
        string username,
        string password,
        string fromEmail,
        string fromName)
    {
        _host = host;
        _port = port;
        _enableSsl = enableSsl;
        _username = username;
        _password = password;
        _fromEmail = fromEmail;
        _fromName = string.IsNullOrWhiteSpace(fromName) ? fromEmail : fromName;
    }

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
    {
        using var client = new SmtpClient(_host, _port)
        {
            EnableSsl = _enableSsl,
            Credentials = new NetworkCredential(_username, _password)
        };

        using var message = new MailMessage
        {
            From = new MailAddress(_fromEmail, _fromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = false
        };
        message.To.Add(new MailAddress(to));

        // SmtpClient in .NET Framework is sync-only for Send; use Task.Run to avoid blocking caller thread
        await Task.Run(() => client.Send(message), ct);
    }
}
