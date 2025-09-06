using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/token")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly IClientAppService _clientApps;
    private readonly IKeyRingService _keyRing;
    private readonly IConfiguration _config;
    public TokenController(IClientAppService clientApps, IKeyRingService keyRing, IConfiguration config)
    {
        _clientApps = clientApps; _keyRing = keyRing; _config = config;
    }

    public record ClientCredentialsRequest(Guid ClientId, string ClientSecret, string Scope);

    [HttpPost("client")]
    [AllowAnonymous]
    public async Task<IActionResult> ClientCredentials([FromBody] ClientCredentialsRequest req)
    {
        var requestedScopes = (req.Scope ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var app = await _clientApps.ValidateAsync(req.ClientId, req.ClientSecret, requestedScopes);
        if (app == null) return Unauthorized();
    var key = await _keyRing.GetActiveSigningKeyAsync();
    var rsa = RSA.Create();
    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(key.Secret), out _);
    var creds = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = key.Kid }, SecurityAlgorithms.RsaSha256);
        var claims = new List<Claim> { new Claim("client_id", app.Id.ToString()) };
        foreach (var sc in requestedScopes) claims.Add(new Claim("scope", sc));
        var tokenLifetimeMinutes = int.TryParse(_config["JWT:AccessTokenMinutes"], out var m) ? m : 60;
        var token = new JwtSecurityToken(
            issuer: _config["JWT:ValidIssuer"],
            audience: _config["JWT:ValidAudience"],
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(tokenLifetimeMinutes),
            signingCredentials: creds);
        token.Header["kid"] = key.Kid;
        return Ok(new { access_token = new JwtSecurityTokenHandler().WriteToken(token), token_type = "bearer", expires = token.ValidTo });
    }
}
