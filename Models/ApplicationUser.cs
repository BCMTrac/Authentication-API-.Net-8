using Microsoft.AspNetCore.Identity;

namespace AuthenticationAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
    public string? TenantId { get; set; } // For future multi-tenant support
    public int TokenVersion { get; set; } = 0; // Increment to invalidate existing access tokens
    }
}