namespace AuthenticationAPI.Models.Options;

public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimiting";
    public int PermitLimit { get; set; } = 10;
    public int WindowSeconds { get; set; } = 60;
    public int QueueLimit { get; set; } = 0;
    public string PolicyName { get; set; } = "auth";
}
