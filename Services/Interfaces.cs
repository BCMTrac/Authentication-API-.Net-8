using AuthenticationAPI.Models;
using System.Security.Claims;

namespace AuthenticationAPI.Services;

public interface IKeyRingService
{
    Task<SigningKey> GetActiveSigningKeyAsync();
    Task<IReadOnlyCollection<SigningKey>> GetAllActiveKeysAsync();
    Task<SigningKey> RotateAsync();
}

public interface ITotpService
{
    string GenerateSecret();
    string GetOtpAuthUrl(string secret, string userEmail, string issuer);
    bool ValidateCode(string secret, string code, out long timeStepMatched);
}
