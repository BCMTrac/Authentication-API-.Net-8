namespace AuthenticationAPI.Services.Email;

public interface IEmailSender
{
    void QueueSendAsync(string to, string subject, string body);
}
