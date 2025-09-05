using System.Security.Cryptography;
using System.Text;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Services;

public interface IClientAppService
{
    Task<(ClientApp app, string plainSecret)> CreateAsync(string name, IEnumerable<string> scopes);
    Task<ClientApp?> ValidateAsync(Guid id, string secret, IEnumerable<string> requestedScopes);
}

public class ClientAppService : IClientAppService
{
    private readonly ApplicationDbContext _db;
    public ClientAppService(ApplicationDbContext db) => _db = db;

    public async Task<(ClientApp app, string plainSecret)> CreateAsync(string name, IEnumerable<string> scopes)
    {
        var plain = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var hash = Hash(plain);
        var app = new ClientApp
        {
            Name = name,
            SecretHash = hash,
            AllowedScopes = string.Join(' ', scopes.Distinct())
        };
        _db.ClientApps.Add(app);
        await _db.SaveChangesAsync();
        return (app, plain);
    }

    public async Task<ClientApp?> ValidateAsync(Guid id, string secret, IEnumerable<string> requestedScopes)
    {
        var hash = Hash(secret);
        var app = await _db.ClientApps.FirstOrDefaultAsync(c => c.Id == id && c.Active && c.SecretHash == hash);
        if (app == null) return null;
        var allowed = app.AllowedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!requestedScopes.All(rs => allowed.Contains(rs))) return null;
        return app;
    }

    private static string Hash(string input)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input)));
    }
}
