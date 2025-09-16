using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Services
{
    public class OnboardingService : IOnboardingService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITenantService _tenantService;

        public OnboardingService(UserManager<ApplicationUser> userManager, ITenantService tenantService)
        {
            _userManager = userManager;
            _tenantService = tenantService;
        }

        public async Task<string> CreateTenantAsync(TenantOnboardingDto tenantDto)
        {
            var tenant = await _tenantService.CreateTenantAsync(tenantDto);
            return tenant.Id;
        }

        public async Task<ApplicationUser> CreateTenantAdminAsync(AdminOnboardingDto adminDto)
        {
            var user = new ApplicationUser
            {
                UserName = adminDto.Email,
                Email = adminDto.Email,
                FullName = $"{adminDto.FirstName} {adminDto.LastName}",
                PhoneNumber = adminDto.Phone,
                TenantId = adminDto.TenantId,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user);

            if (!result.Succeeded)
            {
                throw new TenantAdminCreationException($"Could not create tenant admin: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            await _userManager.AddToRoleAsync(user, "Admin");

            return user;
        }
    }
}