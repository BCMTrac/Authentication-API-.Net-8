using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services;

public interface IRefreshTokenService
{
    Task<(string refreshToken, DateTime expiresUtc)> IssueAsync(ApplicationUser user, string ip);
    // Overload to issue refresh token linked to a session
    Task<(string refreshToken, DateTime expiresUtc)> IssueAsync(ApplicationUser user, string ip, Guid sessionId);
    Task<bool> RevokeAsync(string refreshToken, string ip, string reason);
    Task<RefreshToken?> ValidateAsync(string refreshToken);
    Task RevokeAndLinkAsync(string oldRefreshToken, string newRefreshToken, string ip);
    Task<bool> HandleReuseAttemptAsync(string refreshToken);
    Task<int> RevokeAllForUserAsync(string userId, string reason);
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

    public async Task<(string refreshToken, DateTime expiresUtc)> IssueAsync(ApplicationUser user, string ip, Guid sessionId)
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
                CreatedIp = ip,
                SessionId = sessionId
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

    public async Task RevokeAndLinkAsync(string oldRefreshToken, string newRefreshToken, string ip)
    {
        var oldHash = Hash(oldRefreshToken);
        var newHash = Hash(newRefreshToken);
        using var tx = await _db.Database.BeginTransactionAsync();
        try
        {
            var entity = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == oldHash && r.RevokedUtc == null);
            if (entity != null)
            {
                entity.RevokedUtc = DateTime.UtcNow;
                entity.RevokedReason = "rotation";
                entity.ReplacedByTokenHash = newHash;
                await _db.SaveChangesAsync();
                await tx.CommitAsync();
            }
            else
            {
                await tx.RollbackAsync();
            }
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }

    public async Task<bool> HandleReuseAttemptAsync(string refreshToken)
    {
        var hash = Hash(refreshToken);
        // Look up even if revoked
        var entity = await _db.RefreshTokens.Include(r => r.User).FirstOrDefaultAsync(r => r.TokenHash == hash);
        if (entity == null) return false;
        // A reuse attempt is defined as: token exists, was revoked due to rotation previously
        if (entity.RevokedUtc != null && string.Equals(entity.RevokedReason, "rotation", StringComparison.OrdinalIgnoreCase))
        {
            var userId = entity.UserId;
            using var tx = await _db.Database.BeginTransactionAsync();
            try
            {
                // Revoke all active refresh tokens for this user
                var now = DateTime.UtcNow;
                var tokens = await _db.RefreshTokens.Where(r => r.UserId == userId && r.RevokedUtc == null).ToListAsync();
                foreach (var t in tokens)
                {
                    t.RevokedUtc = now;
                    t.RevokedReason = "reuse-detected";
                }
                // Bump token version to invalidate access tokens
                var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user != null)
                {
                    user.TokenVersion += 1;
                }
                await _db.SaveChangesAsync();
                await tx.CommitAsync();
                return true;
            }
            catch
            {
                await tx.RollbackAsync();
                return false;
            }
        }
        return false;
    }

    public async Task<int> RevokeAllForUserAsync(string userId, string reason)
    {
        var tokens = await _db.RefreshTokens.Where(r => r.UserId == userId && r.RevokedUtc == null).ToListAsync();
        foreach (var t in tokens)
        {
            t.RevokedUtc = DateTime.UtcNow;
            t.RevokedReason = reason;
        }
        await _db.SaveChangesAsync();
        return tokens.Count;
    }

    private static string Hash(string token)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }
}
