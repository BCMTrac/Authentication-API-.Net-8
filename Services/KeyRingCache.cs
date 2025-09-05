using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.Text;
using AuthenticationAPI.Models;
using System.Collections.Generic;
using System.Security.Cryptography;
using System;

namespace AuthenticationAPI.Services;

public interface IKeyRingCache
{
    IReadOnlyCollection<SecurityKey> GetAll();
    IReadOnlyCollection<SecurityKey> GetByKid(string? kid);
    void Set(IEnumerable<SigningKey> keys);
}

public class KeyRingCache : IKeyRingCache
{
    private readonly ConcurrentDictionary<string, SecurityKey> _keys = new();
    public IReadOnlyCollection<SecurityKey> GetAll() => _keys.Values.ToList();
    public IReadOnlyCollection<SecurityKey> GetByKid(string? kid)
        => string.IsNullOrWhiteSpace(kid) ? GetAll() : _keys.TryGetValue(kid, out var key) ? new[] { key } : Array.Empty<SecurityKey>();
    public void Set(IEnumerable<SigningKey> keys)
    {
        _keys.Clear();
        foreach (var k in keys.Where(k => k.Active && k.Algorithm.StartsWith("RS", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                var pub = Convert.FromBase64String(k.PublicKey ?? string.Empty);
                var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(pub, out _);
                var sec = new RsaSecurityKey(rsa) { KeyId = k.Kid };
                _keys[k.Kid] = sec;
            }
            catch { /* skip malformed */ }
        }
    }
}
