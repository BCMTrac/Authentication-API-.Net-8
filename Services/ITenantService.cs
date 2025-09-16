using AuthenticationAPI.Models;
using System.Threading.Tasks;

namespace AuthenticationAPI.Services
{
    public interface ITenantService
    {
        Task<Tenant> CreateTenantAsync(TenantOnboardingDto tenantDto);
        Task<bool> IsSubdomainTakenAsync(string subdomain);
    }
}
