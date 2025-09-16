using System.Threading.Tasks;

namespace AuthenticationAPI.Services
{
    public interface IAuditService
    {
        Task LogAsync(string action, string? targetEntityType = null, string? targetEntityId = null, object? details = null);
    }
}
