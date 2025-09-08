using Microsoft.Extensions.Caching.Memory;

namespace AuthenticationAPI.Services.Throttle;

public sealed class MemoryThrottleService : IThrottleService
{
    private readonly IMemoryCache _cache;
    public MemoryThrottleService(IMemoryCache cache) => _cache = cache;

    private sealed class Counter
    {
        public int Count;
        public DateTimeOffset ResetAt;
    }

    public Task<bool> AllowAsync(string key, int limit, TimeSpan window, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = _cache.Get<Counter>(key);
        if (entry == null || entry.ResetAt <= now)
        {
            entry = new Counter { Count = 0, ResetAt = now.Add(window) };
            var opts = new MemoryCacheEntryOptions { AbsoluteExpiration = entry.ResetAt };
            _cache.Set(key, entry, opts);
        }
        if (entry.Count >= limit)
        {
            return Task.FromResult(false);
        }
        entry.Count++;
        return Task.FromResult(true);
    }
}

