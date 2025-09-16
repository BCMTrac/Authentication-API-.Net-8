using AuthenticationAPI.Services.Email;
using Hangfire;

namespace AuthenticationAPI.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IBackgroundJobClient _jobClient;

        public SmtpEmailSender(IBackgroundJobClient jobClient)
        {
            _jobClient = jobClient;
        }

        public void QueueSendAsync(string to, string subject, string body)
        {
            _jobClient.Enqueue<IEmailJob>(job => job.SendAsync(to, subject, body));
        }
    }
}
