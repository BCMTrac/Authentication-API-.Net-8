namespace AuthenticationAPI.Services;

public interface IPasswordBreachChecker
{
    Task<bool> IsCompromisedAsync(string password, CancellationToken ct = default);
}

/// <summary>
/// Default no-op implementation; always returns false. Replace with HIBP k-anonymity checker
/// when network access is permitted.
/// </summary>
public sealed class NoOpPasswordBreachChecker : IPasswordBreachChecker
{
    public Task<bool> IsCompromisedAsync(string password, CancellationToken ct = default) => Task.FromResult(false);
}

