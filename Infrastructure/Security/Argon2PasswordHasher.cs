using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using System.Text.Json;
using Konscious.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Infrastructure.Security;

public class Argon2PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private record Argon2HashPayload(string Alg, int V, int M, int T, int P, string Salt, string Hash);

    // Default parameters (can tune via config later)
    private const int SaltSize = 16; // 128-bit salt
    private const int MemoryKb = 128 * 1024; // 128 MB
    private const int Iterations = 3; // Time cost
    private const int DegreeOfParallelism = 2; // Lanes
    private const int HashLength = 32; // 256-bit output

    public string HashPassword(TUser user, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = DegreeOfParallelism,
            Iterations = Iterations,
            MemorySize = MemoryKb
        };
        var hashBytes = argon.GetBytes(HashLength);
        var payload = new Argon2HashPayload("argon2id", 19, MemoryKb, Iterations, DegreeOfParallelism,
            Convert.ToBase64String(salt), Convert.ToBase64String(hashBytes));
        return JsonSerializer.Serialize(payload);
    }

    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (!hashedPassword.TrimStart().StartsWith("{"))
        {
            // Let Identity fallback: we cannot verify here; treat as Failed so external rehash strategy can apply
            return PasswordVerificationResult.Failed;
        }
        Argon2HashPayload? payload;
        try { payload = JsonSerializer.Deserialize<Argon2HashPayload>(hashedPassword); }
        catch { return PasswordVerificationResult.Failed; }
        if (payload == null || payload.Alg != "argon2id") return PasswordVerificationResult.Failed;
        var salt = Convert.FromBase64String(payload.Salt);
        var argon = new Argon2id(Encoding.UTF8.GetBytes(providedPassword))
        {
            Salt = salt,
            DegreeOfParallelism = payload.P,
            Iterations = payload.T,
            MemorySize = payload.M
        };
        var computed = Convert.ToBase64String(argon.GetBytes(Convert.FromBase64String(payload.Hash).Length));
        if (computed == payload.Hash) return PasswordVerificationResult.Success;
        return PasswordVerificationResult.Failed;
    }
}