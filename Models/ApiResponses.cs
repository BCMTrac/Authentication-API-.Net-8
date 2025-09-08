namespace AuthenticationAPI.Models;

public sealed class ApiMessage
{
    public string Message { get; init; } = string.Empty;
}

public sealed class SentResponse
{
    public bool Sent { get; init; }
}

public sealed class EmailConfirmedResponse
{
    public bool EmailConfirmed { get; init; }
}

public sealed class MfaRequiredResponse
{
    public bool MfaRequired { get; init; }
}

public sealed class TokenSetResponse
{
    public string Token { get; init; } = string.Empty;
    public DateTime Expiration { get; init; }
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime RefreshTokenExpiration { get; init; }
}

public sealed class OtpAuthResponse
{
    public string Secret { get; init; } = string.Empty;
    public string OtpauthUrl { get; init; } = string.Empty;
}

public sealed class MfaEnabledResponse
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> RecoveryCodes { get; init; } = Array.Empty<string>();
}

public sealed class RecoveryCodesResponse
{
    public IReadOnlyList<string> RecoveryCodes { get; init; } = Array.Empty<string>();
}

