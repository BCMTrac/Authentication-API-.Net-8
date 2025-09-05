using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services;

public interface IRecoveryCodeService
{
    Task<IReadOnlyList<string>> GenerateAsync(ApplicationUser user, int count = 10);
    Task<bool> RedeemAsync(ApplicationUser user, string code, string ipAddress);
}

public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private readonly ApplicationDbContext _db;
    public RecoveryCodeService(ApplicationDbContext db) => _db = db;

    public async Task<IReadOnlyList<string>> GenerateAsync(ApplicationUser user, int count = 10)
    {
        // Each code: 10 characters alnum, easy to type. Return plaintext once.
        var codes = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            var code = GenerateCode();
            var hash = Hash(code);
            _db.UserRecoveryCodes.Add(new UserRecoveryCode { UserId = user.Id, CodeHash = hash });
            codes.Add(code);
        }
        await _db.SaveChangesAsync();
        return codes;
    }

    public async Task<bool> RedeemAsync(ApplicationUser user, string code, string ipAddress)
    {
        var hash = Hash(code);
        var rec = await _db.UserRecoveryCodes
            .Where(r => r.UserId == user.Id && r.CodeHash == hash && r.RedeemedUtc == null)
            .FirstOrDefaultAsync();
        if (rec == null) return false;
        rec.RedeemedUtc = DateTime.UtcNow;
        rec.RedeemedIp = ipAddress;
        await _db.SaveChangesAsync();
        return true;
    }

    private static string GenerateCode()
    {
        const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // avoid ambiguous
        Span<byte> buf = stackalloc byte[12];
        RandomNumberGenerator.Fill(buf);
        var sb = new StringBuilder(12);
        foreach (var b in buf) sb.Append(chars[b % chars.Length]);
        return sb.ToString();
    }

    private static string Hash(string code)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(code));
        return Convert.ToHexString(bytes);
    }
}
