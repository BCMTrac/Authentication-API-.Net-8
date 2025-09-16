using AuthenticationAPI.Models;
using System.Threading.Tasks;

namespace AuthenticationAPI.Services
{
    public interface IOnboardingService
    {
        Task<string> CreateTenantAsync(TenantOnboardingDto tenantDto);
        Task<ApplicationUser> CreateTenantAdminAsync(AdminOnboardingDto adminDto);
    }
}
