namespace AuthenticationAPI.Services.Throttle;

public interface IThrottleService
{
    Task<bool> AllowAsync(string key, int limit, TimeSpan window, CancellationToken ct = default);
}

