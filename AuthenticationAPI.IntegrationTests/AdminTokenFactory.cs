using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationAPI.IntegrationTests;

public static class AdminTokenFactory
{
    public static async Task<string> CreateAdminAsync(TestApplicationFactory factory, string? existingUserName = null)
    {
        var client = factory.CreateClient();
        string email = existingUserName == null ? $"admin_{Guid.NewGuid():N}@example.com" : existingUserName + "@example.com";
        string username = existingUserName ?? $"admin_{Guid.NewGuid():N}";
        string password = "Adm1n$tr0ngP@ss!";
        await client.PostAsJsonAsync("/api/v1/authenticate/register", new { Email = email, Username = username, Password = password, TermsAccepted = true });
        using var scope = factory.Services.CreateScope();
        var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roleMgr.RoleExistsAsync("Admin")) await roleMgr.CreateAsync(new IdentityRole("Admin"));
        var user = await userMgr.FindByNameAsync(username);
        var token = await userMgr.GenerateEmailConfirmationTokenAsync(user!);
        await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token });
        user = await userMgr.FindByNameAsync(username);
        if (!await userMgr.IsInRoleAsync(user!, "Admin")) await userMgr.AddToRoleAsync(user!, "Admin");
        // Mint token directly
        var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
    var keyRingSvc = scope.ServiceProvider.GetService(typeof(AuthenticationAPI.Services.IKeyRingService)) as AuthenticationAPI.Services.IKeyRingService;
    if (keyRingSvc == null) throw new InvalidOperationException("IKeyRingService not found");
    var activeKey = await keyRingSvc.GetActiveSigningKeyAsync();
    var kid = activeKey.Kid;
    var secret = activeKey.Secret;
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(secret), out _);
        var creds = new SigningCredentials(new RsaSecurityKey(rsa){KeyId = kid}, SecurityAlgorithms.RsaSha256);
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.NameIdentifier, user!.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("token_version", user.TokenVersion.ToString()),
            new Claim(ClaimTypes.Role, "User"),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim("sid", Guid.NewGuid().ToString())
        };
        var tokenJwt = new JwtSecurityToken(
            issuer: configuration["JWT:ValidIssuer"],
            audience: configuration["JWT:ValidAudience"],
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds);
        tokenJwt.Header["kid"] = kid;
        return new JwtSecurityTokenHandler().WriteToken(tokenJwt);
    }
}
