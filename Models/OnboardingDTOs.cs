namespace AuthenticationAPI.Models
{
    public class TenantOnboardingDto
    {
        public string CompanyName { get; set; } = string.Empty;
        public string Subdomain { get; set; } = string.Empty;
        public string Country { get; set; } = string.Empty;
        public string Currency { get; set; } = string.Empty;
        public string TimeZone { get; set; } = string.Empty;
        public string Plan { get; set; } = string.Empty;
        public bool MfaRequired { get; set; }
        public bool PopiaDpaAgreed { get; set; }
    }

    public class AdminOnboardingDto
    {
        public string TenantId { get; set; } = string.Empty; // Assuming tenant is created first
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? Phone { get; set; }
    }

    public class BulkInviteDto
    {
        public string TenantId { get; set; } = string.Empty;
        public string Invites { get; set; } = string.Empty; // Expecting a comma-separated list of emails
    }
}
