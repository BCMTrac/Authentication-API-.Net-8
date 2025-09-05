using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.Text;
using AuthenticationAPI.Models;

namespace AuthenticationAPI.Services;

public interface IKeyRingCache
{
    IReadOnlyCollection<SecurityKey> GetAll();
    IReadOnlyCollection<SecurityKey> GetByKid(string? kid);
    void Set(IEnumerable<SigningKey> keys);
}

public class KeyRingCache : IKeyRingCache
{
    private readonly ConcurrentDictionary<string, SymmetricSecurityKey> _keys = new();
    public IReadOnlyCollection<SecurityKey> GetAll() => _keys.Values.ToList();
    public IReadOnlyCollection<SecurityKey> GetByKid(string? kid)
        => string.IsNullOrWhiteSpace(kid) ? GetAll() : _keys.TryGetValue(kid, out var key) ? new[] { key } : Array.Empty<SecurityKey>();
    public void Set(IEnumerable<SigningKey> keys)
    {
        _keys.Clear();
        foreach (var k in keys.Where(k => k.Active))
        {
            var sec = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(k.Secret));
            sec.KeyId = k.Kid;
            _keys[k.Kid] = sec;
        }
    }
}
