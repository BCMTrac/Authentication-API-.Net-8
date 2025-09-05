using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationAPI.Services;

public sealed class DataProtectionMfaSecretProtector : IMfaSecretProtector
{
    private readonly IDataProtector _protector;
    public DataProtectionMfaSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("AuthenticationAPI.MFA.Secret");
    }

    public string Protect(string plaintext)
        => _protector.Protect(plaintext);

    public string Unprotect(string protectedValue)
    {
        try { return _protector.Unprotect(protectedValue); }
        catch { return string.Empty; }
    }
}
