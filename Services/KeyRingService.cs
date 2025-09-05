using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using AuthenticationAPI.Models.Options;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services;

public class KeyRingService : IKeyRingService
{
    private readonly ApplicationDbContext _db;
    private readonly KeyRotationOptions _rotationOptions;
    public KeyRingService(ApplicationDbContext db, IOptions<KeyRotationOptions> rotationOptions)
    {
        _db = db;
        _rotationOptions = rotationOptions.Value;
    }

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
            Secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(_rotationOptions.KeyBytes)),
            Active = true
        };
        _db.SigningKeys.Add(newKey);
        var keep = Math.Max(1, _rotationOptions.OverlapActiveKeyCount);
        var active = await _db.SigningKeys.Where(k => k.Active).OrderByDescending(k => k.CreatedUtc).ToListAsync();
        if (active.Count > keep)
        {
            foreach (var retire in active.Skip(keep))
            {
                retire.Active = false;
                retire.RetiredUtc = DateTime.UtcNow;
            }
        }
        await _db.SaveChangesAsync();
        return newKey;
    }
}
