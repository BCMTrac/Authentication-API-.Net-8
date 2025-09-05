namespace AuthenticationAPI.Models.Options;

public sealed class JwtOptions
{
    public const string SectionName = "JWT";
    public string ValidAudience { get; set; } = string.Empty;
    public string ValidIssuer { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 60; // default
}
