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
        using var rsa = RSA.Create(_rotationOptions.RsaKeySize);
        var privateKey = rsa.ExportPkcs8PrivateKey();
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var newKey = new SigningKey
        {
            Kid = Guid.NewGuid().ToString("N").Substring(0, 16),
            Algorithm = "RS256",
            Secret = Convert.ToBase64String(privateKey),
            PublicKey = Convert.ToBase64String(publicKey),
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
