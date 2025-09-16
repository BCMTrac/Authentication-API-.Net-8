using AuthenticationAPI.Models.Options;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace AuthenticationAPI.Services.Email
{
    public class EmailJob : IEmailJob
    {
        private readonly SmtpOptions _options;

        public EmailJob(IOptions<SmtpOptions> options)
        {
            _options = options.Value;
        }

        public async Task SendAsync(string to, string subject, string body)
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
                Body = body,
                IsBodyHtml = !string.IsNullOrWhiteSpace(body) && (body.TrimStart().StartsWith("<") && body.TrimEnd().EndsWith(">"))
            };
            msg.To.Add(new MailAddress(to));

            await client.SendMailAsync(msg);
        }
    }
}
