using Microsoft.Extensions.Diagnostics.HealthChecks;
using AuthenticationAPI.Data;

namespace AuthenticationAPI.Infrastructure.Health;

public class DatabaseHealthCheck : IHealthCheck
{
    private readonly ApplicationDbContext _db;
    public DatabaseHealthCheck(ApplicationDbContext db) => _db = db;

    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var can = _db.Database.CanConnect();
            return Task.FromResult(can ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy("Cannot connect"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Exception", ex));
        }
    }
}
