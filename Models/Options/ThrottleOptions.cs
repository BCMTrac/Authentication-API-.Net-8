namespace AuthenticationAPI.Models.Options;

public sealed class ThrottleOptions
{
    public const string SectionName = "Throttle";
    public string Provider { get; set; } = "memory"; // memory | redis
    public string? RedisConnectionString { get; set; }
}

