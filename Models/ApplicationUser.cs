using Microsoft.AspNetCore.Identity;

namespace AuthenticationAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
    public string? FullName { get; set; }
    public int TokenVersion { get; set; } = 0; // Increment to invalidate existing access tokens
    public bool MfaEnabled { get; set; } = false; // TOTP enabled flag
    public string? MfaSecret { get; set; } // Base32 secret (encrypted at rest in production)
    public long MfaLastTimeStep { get; set; } = -1; // anti-replay: last accepted TOTP time step
    }
}
