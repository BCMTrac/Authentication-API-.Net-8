using System.Net;
using System.Net.Mail;
using AuthenticationAPI.Models.Options;

namespace AuthenticationAPI.Services.Email;

public sealed class SmtpEmailSender : IEmailSender
{
	private readonly SmtpOptions _options;
	public SmtpEmailSender(SmtpOptions options) => _options = options;

	public async Task SendAsync(string to, string subject, string body, CancellationToken ct = default)
	{
		using var client = new SmtpClient(_options.Host, _options.Port)
		{
			EnableSsl = _options.UseSsl,
			Credentials = (!string.IsNullOrWhiteSpace(_options.Username) && !string.IsNullOrWhiteSpace(_options.Password))
				? new NetworkCredential(_options.Username, _options.Password)
				: CredentialCache.DefaultNetworkCredentials
		};
		using var msg = new MailMessage()
		{
			From = new MailAddress(_options.From, string.IsNullOrWhiteSpace(_options.FromName) ? _options.From : _options.FromName),
			Subject = subject,
			Body = body
		};
		msg.To.Add(new MailAddress(to));
		await client.SendMailAsync(msg, ct);
	}
}
