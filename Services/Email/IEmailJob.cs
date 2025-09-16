using System.Threading.Tasks;

namespace AuthenticationAPI.Services.Email
{
    public interface IEmailJob
    {
        Task SendAsync(string to, string subject, string body);
    }
}
