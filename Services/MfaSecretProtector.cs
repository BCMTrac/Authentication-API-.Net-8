using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationAPI.Services;

public interface IMfaSecretProtector
{
    string Protect(string plain);
    string Unprotect(string protectedValue);
}

public class MfaSecretProtector : IMfaSecretProtector
{
    private readonly IDataProtector _protector;
    public MfaSecretProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("MFASecret.v1");
    }
    public string Protect(string plain) => _protector.Protect(plain);
    public string Unprotect(string protectedValue)
    {
        try { return _protector.Unprotect(protectedValue); } catch { return string.Empty; }
    }
}
