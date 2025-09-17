using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Controllers
{
    [Route("api/v1/onboarding")]
    [ApiController]
    [Authorize(Roles = "Admin", AuthenticationSchemes = "Identity.Application,Bearer")] // Only admins can access onboarding APIs
    public class OnboardingController : ControllerBase
    {
        private readonly IOnboardingService _onboardingService;
        private readonly ILogger<OnboardingController> _logger;
        private readonly IAuditService _auditService;

        public OnboardingController(IOnboardingService onboardingService, ILogger<OnboardingController> logger, IAuditService auditService)
        {
            _onboardingService = onboardingService;
            _logger = logger;
            _auditService = auditService;
        }

        [HttpPost("tenant")]
        public async Task<IActionResult> CreateTenant([FromBody] TenantOnboardingDto tenantDto)
        {
            if (!ModelState.IsValid)
            {
                return ValidationProblem(ModelState);
            }

            _logger.LogInformation("Starting onboarding for new tenant {CompanyName}", tenantDto.CompanyName);
            try
            {
                var tenantId = await _onboardingService.CreateTenantAsync(tenantDto);
                await _auditService.LogAsync("TenantCreated", nameof(Tenant), tenantId, tenantDto);
                return Ok(new { tenantId });
            }
            catch (SubdomainTakenException ex)
            {
                _logger.LogWarning(ex, "Subdomain {Subdomain} is already taken.", tenantDto.Subdomain);
                throw;
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Failed to create tenant {CompanyName}", tenantDto.CompanyName);
                throw new TenantCreationException("An unexpected error occurred during tenant creation.");
            }
        }

        [HttpPost("admin")]
        public async Task<IActionResult> CreateAdmin([FromBody] AdminOnboardingDto adminDto)
        {
            if (!ModelState.IsValid)
            {
                return ValidationProblem(ModelState);
            }

            try
            {
                _logger.LogInformation("Creating primary admin {Email} for tenant {TenantId}", adminDto.Email, adminDto.TenantId);
                var user = await _onboardingService.CreateTenantAdminAsync(adminDto);
                await _auditService.LogAsync("TenantAdminCreated", nameof(ApplicationUser), user.Id, adminDto);
                return Ok(new { userId = user.Id });
            }
            catch (System.Exception ex)
            {
                _logger.LogError(ex, "Failed to create primary admin for tenant {TenantId}", adminDto.TenantId);
                throw new TenantAdminCreationException("An unexpected error occurred during tenant administrator creation.");
            }
        }
    }
}
