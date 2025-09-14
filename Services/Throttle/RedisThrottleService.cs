using StackExchange.Redis;

namespace AuthenticationAPI.Services.Throttle;

public sealed class RedisThrottleService : IThrottleService, IAsyncDisposable
{
    private readonly ConnectionMultiplexer _mux;
    private readonly IDatabase _db;

    public RedisThrottleService(string connectionString)
    {
        _mux = ConnectionMultiplexer.Connect(connectionString);
        _db = _mux.GetDatabase();
    }

    // Use Redis INCR with TTL to implement fixed window counters
    public async Task<bool> AllowAsync(string key, int limit, TimeSpan window, CancellationToken ct = default)
    {
        // Use a namespaced key
        var redisKey = new RedisKey($"throttle:{key}");
        var count = await _db.StringIncrementAsync(redisKey);
        if (count == 1)
        {
            // First increment: set expiration for the window
            await _db.KeyExpireAsync(redisKey, window);
        }
        return count <= limit;
    }

    public async ValueTask DisposeAsync()
    {
        await _mux.CloseAsync();
        _mux.Dispose();
    }
}

