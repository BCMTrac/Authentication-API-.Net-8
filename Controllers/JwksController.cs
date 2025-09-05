using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using AuthenticationAPI.Models;

namespace AuthenticationAPI.Controllers;

[ApiController]
[Route(".well-known/jwks.json")]
public class JwksController : ControllerBase
{
    private readonly IKeyRingService _keyRing;
    public JwksController(IKeyRingService keyRing) { _keyRing = keyRing; }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var keys = await _keyRing.GetAllActiveKeysAsync();
        var jwks = new
        {
            keys = keys
                .Where(k => k.Algorithm.StartsWith("RS"))
                .Select(k => ToJwk(k))
                .ToArray()
        };
        return Ok(jwks);
    }

    private static object ToJwk(SigningKey k)
    {
        try
        {
            var pub = Convert.FromBase64String(k.PublicKey ?? "");
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(pub, out _);
            var parameters = rsa.ExportParameters(false);
            string B64Url(byte[] bytes) => Base64UrlEncoder.Encode(bytes);
            return new
            {
                kty = "RSA",
                use = "sig",
                alg = "RS256",
                kid = k.Kid,
                n = B64Url(parameters.Modulus!),
                e = B64Url(parameters.Exponent!)
            };
        }
        catch
        {
            return new { }; // filtered out by consumer
        }
    }
}