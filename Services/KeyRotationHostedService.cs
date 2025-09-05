using AuthenticationAPI.Data;
using AuthenticationAPI.Models.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services;

public class KeyRotationHostedService : BackgroundService
{
    private readonly IServiceProvider _provider;
    private readonly KeyRotationOptions _options;
    private readonly ILogger<KeyRotationHostedService> _logger;

    public KeyRotationHostedService(IServiceProvider provider, IOptions<KeyRotationOptions> options, ILogger<KeyRotationHostedService> logger)
    {
        _provider = provider;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.IntervalHours <= 0)
        {
            _logger.LogInformation("Key rotation disabled (IntervalHours <= 0)");
            return;
        }

        var interval = TimeSpan.FromHours(_options.IntervalHours);
        // Simple loop using delay; production could use PeriodicTimer
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _provider.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var keySvc = scope.ServiceProvider.GetRequiredService<IKeyRingService>();
                var cache = scope.ServiceProvider.GetRequiredService<IKeyRingCache>();
                var newest = await db.SigningKeys.Where(k => k.Active).OrderByDescending(k => k.CreatedUtc).FirstOrDefaultAsync(stoppingToken);
                if (newest == null)
                {
                    _logger.LogWarning("No active signing key found, creating initial key");
                    await keySvc.RotateAsync();
                    cache.Set(await keySvc.GetAllActiveKeysAsync());
                }
                else if (DateTime.UtcNow - newest.CreatedUtc >= interval)
                {
                    var newKey = await keySvc.RotateAsync();
                    cache.Set(await keySvc.GetAllActiveKeysAsync());
                    _logger.LogInformation("Rotated signing key. New kid={Kid}", newKey.Kid);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during key rotation check");
            }

            try { await Task.Delay(TimeSpan.FromMinutes(15), stoppingToken); } catch { }
        }
    }
}
