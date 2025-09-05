using AuthenticationAPI.Services;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AuthenticationAPI.Infrastructure.Health;

public class KeyRingHealthCheck : IHealthCheck
{
    private readonly IKeyRingCache _cache;
    public KeyRingHealthCheck(IKeyRingCache cache) { _cache = cache; }

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var keys = _cache.GetAll();
        if (keys.Count == 0)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("No signing keys available in cache"));
        }
        return Task.FromResult(HealthCheckResult.Healthy());
    }
}

