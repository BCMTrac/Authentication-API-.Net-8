using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services;

public interface IRefreshTokenService
{
    Task<(string refreshToken, DateTime expiresUtc)> IssueAsync(ApplicationUser user, string ip);
    Task<bool> RevokeAsync(string refreshToken, string ip, string reason);
    Task<RefreshToken?> ValidateAsync(string refreshToken);
}

public class RefreshTokenService : IRefreshTokenService
{
    private readonly ApplicationDbContext _db;
    private readonly TimeSpan _lifetime = TimeSpan.FromDays(7);

    public RefreshTokenService(ApplicationDbContext db) => _db = db;

    public async Task<(string refreshToken, DateTime expiresUtc)> IssueAsync(ApplicationUser user, string ip)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var hash = Hash(token);
        using var tx = await _db.Database.BeginTransactionAsync();
        try
        {
            var entity = new RefreshToken
            {
                UserId = user.Id,
                TokenHash = hash,
                ExpiresUtc = DateTime.UtcNow.Add(_lifetime),
                CreatedIp = ip
            };
            _db.RefreshTokens.Add(entity);
            await _db.SaveChangesAsync();
            await tx.CommitAsync();
            return (token, entity.ExpiresUtc);
        }
        catch (DbUpdateConcurrencyException)
        {
            await tx.RollbackAsync();
            throw;
        }
    }

    public async Task<bool> RevokeAsync(string refreshToken, string ip, string reason)
    {
        var hash = Hash(refreshToken);
        using var tx = await _db.Database.BeginTransactionAsync();
        try
        {
            var entity = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash && r.RevokedUtc == null);
            if (entity == null) return false;
            entity.RevokedUtc = DateTime.UtcNow;
            entity.RevokedReason = reason;
            entity.ReplacedByTokenHash = null;
            await _db.SaveChangesAsync();
            await tx.CommitAsync();
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            await tx.RollbackAsync();
            return false;
        }
    }

    public async Task<RefreshToken?> ValidateAsync(string refreshToken)
    {
        var hash = Hash(refreshToken);
        // No transaction needed (read-only); optimistic concurrency not required here.
        var entity = await _db.RefreshTokens.AsNoTracking().Include(r => r.User).FirstOrDefaultAsync(r => r.TokenHash == hash);
        if (entity == null || !entity.IsActive) return null;
        return entity;
    }

    private static string Hash(string token)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }
}
