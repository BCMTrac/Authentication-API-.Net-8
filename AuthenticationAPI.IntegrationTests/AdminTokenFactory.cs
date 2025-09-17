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
    // Generate confirmation token in isolated scope
            string confirmToken;
            using (var scopeGen = factory.Services.CreateScope())
            {
                var userMgrGen = scopeGen.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var roleMgrGen = scopeGen.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                if (!await roleMgrGen.RoleExistsAsync("Admin")) await roleMgrGen.CreateAsync(new IdentityRole("Admin"));
                var userGen = await userMgrGen.FindByNameAsync(username);
                confirmToken = await userMgrGen.GenerateEmailConfirmationTokenAsync(userGen!);
            }
            await client.PostAsJsonAsync("/api/v1/authenticate/confirm-email", new { email, token = confirmToken });
        using var scopeFinal = factory.Services.CreateScope();
        var userMgr = scopeFinal.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userMgr.FindByNameAsync(username);
        if (!await userMgr.IsInRoleAsync(user!, "Admin"))
        {
            var addRes = await userMgr.AddToRoleAsync(user!, "Admin");
            if (!addRes.Succeeded)
            {
                throw new Exception("Failed to assign Admin role: " + string.Join(";", addRes.Errors.Select(e => e.Code + ":" + e.Description)));
            }
        }
        // Mint token directly
    var configuration = scopeFinal.ServiceProvider.GetRequiredService<IConfiguration>();
    var keyRingSvc = scopeFinal.ServiceProvider.GetService(typeof(AuthenticationAPI.Services.IKeyRingService)) as AuthenticationAPI.Services.IKeyRingService;
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
