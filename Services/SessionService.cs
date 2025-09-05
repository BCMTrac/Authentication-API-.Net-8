using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services;

public interface ISessionService
{
    Task<Session> CreateAsync(ApplicationUser user, string ip, string? userAgent, string? deviceId = null);
    Task TouchAsync(Guid sessionId);
    Task<bool> RevokeAsync(Guid sessionId, string reason = "manual");
    Task<int> RevokeAllForUserAsync(string userId, string reason = "manual");
}

public class SessionService : ISessionService
{
    private readonly ApplicationDbContext _db;
    public SessionService(ApplicationDbContext db) => _db = db;

    public async Task<Session> CreateAsync(ApplicationUser user, string ip, string? userAgent, string? deviceId = null)
    {
        var s = new Session { UserId = user.Id, Ip = ip, UserAgent = userAgent, DeviceId = deviceId };
        _db.Sessions.Add(s);
        await _db.SaveChangesAsync();
        return s;
    }

    public async Task TouchAsync(Guid sessionId)
    {
        var s = await _db.Sessions.FindAsync(sessionId);
        if (s != null)
        {
            s.LastSeenUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }
    }

    public async Task<bool> RevokeAsync(Guid sessionId, string reason = "manual")
    {
        var s = await _db.Sessions.FindAsync(sessionId);
        if (s == null) return false;
        s.RevokedAtUtc = DateTime.UtcNow;
        // Revoke all refresh tokens tied to this session
        var tokens = await _db.RefreshTokens.Where(r => r.SessionId == sessionId && r.RevokedUtc == null).ToListAsync();
        foreach (var t in tokens) { t.RevokedUtc = DateTime.UtcNow; t.RevokedReason = reason; }
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<int> RevokeAllForUserAsync(string userId, string reason = "manual")
    {
        var sessions = await _db.Sessions.Where(s => s.UserId == userId && s.RevokedAtUtc == null).ToListAsync();
        foreach (var s in sessions) s.RevokedAtUtc = DateTime.UtcNow;
        var tokens = await _db.RefreshTokens.Where(r => r.UserId == userId && r.RevokedUtc == null).ToListAsync();
        foreach (var t in tokens) { t.RevokedUtc = DateTime.UtcNow; t.RevokedReason = reason; }
        await _db.SaveChangesAsync();
        return sessions.Count;
    }
}

