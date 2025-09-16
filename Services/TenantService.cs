using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Services
{
    public class TenantService : ITenantService
    {
        private readonly ApplicationDbContext _context;

        public TenantService(ApplicationDbContext context)
        { 
            _context = context;
        }

        public async Task<Tenant> CreateTenantAsync(TenantOnboardingDto tenantDto)
        {
            if (await IsSubdomainTakenAsync(tenantDto.Subdomain))
            {
                throw new SubdomainTakenException();
            }

            var tenant = new Tenant
            {
                CompanyName = tenantDto.CompanyName,
                Subdomain = tenantDto.Subdomain,
                Plan = tenantDto.Plan,
                MfaRequired = tenantDto.MfaRequired
            };

            await _context.Tenants.AddAsync(tenant);
            await _context.SaveChangesAsync();

            return tenant;
        }

        public async Task<bool> IsSubdomainTakenAsync(string subdomain)
        {
            return await _context.Tenants.AnyAsync(t => t.Subdomain == subdomain);
        }
    }
}