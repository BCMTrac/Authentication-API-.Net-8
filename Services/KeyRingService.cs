using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace AuthenticationAPI.Services;

public class KeyRingService : IKeyRingService
{
    private readonly ApplicationDbContext _db;
    public KeyRingService(ApplicationDbContext db) => _db = db;

    public async Task<SigningKey> GetActiveSigningKeyAsync()
        => await _db.SigningKeys.Where(k => k.Active).OrderBy(k => k.CreatedUtc).LastAsync();

    public async Task<IReadOnlyCollection<SigningKey>> GetAllActiveKeysAsync()
        => await _db.SigningKeys.Where(k => k.Active).ToListAsync();

    public async Task<SigningKey> RotateAsync()
    {
        // Mark current active keys still active (overlap) but retire ones older than 2 rotations? Simplified for now.
        var newKey = new SigningKey
        {
            Kid = Guid.NewGuid().ToString("N").Substring(0, 16),
            Algorithm = "HS256",
            Secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Active = true
        };
        _db.SigningKeys.Add(newKey);
        // Retire keys older than 2 active keys (keep overlap of last 2)
        var active = await _db.SigningKeys.Where(k => k.Active).OrderByDescending(k => k.CreatedUtc).ToListAsync();
        if (active.Count > 2)
        {
            foreach (var retire in active.Skip(2))
            {
                retire.Active = false;
                retire.RetiredUtc = DateTime.UtcNow;
            }
        }
        await _db.SaveChangesAsync();
        return newKey;
    }
}
