using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Options;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationAPI.Infrastructure.Security;

public class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptions<JwtOptions> _jwt;
    private readonly IKeyRingCache _cache;

    public ConfigureJwtBearerOptions(IOptions<JwtOptions> jwt, IKeyRingCache cache)
    {
        _jwt = jwt; _cache = cache;
    }

    public void Configure(string? name, JwtBearerOptions options) => Configure(options);

    public void Configure(JwtBearerOptions options)
    {
        var jwt = _jwt.Value;
    options.SaveToken = true;
    // Always require HTTPS metadata in production
    options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = jwt.ValidAudience,
            ValidIssuer = jwt.ValidIssuer,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(60),
            NameClaimType = System.Security.Claims.ClaimTypes.Name,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role,
            ValidTypes = new[] { "JWT" },
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                var byKid = _cache.GetByKid(kid);
                return byKid.Count > 0 ? byKid : _cache.GetAll();
            }
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                var user = await userManager.GetUserAsync(context.Principal!);
                var versionClaim = context.Principal!.FindFirst("token_version")?.Value;
                if (user == null || versionClaim == null || versionClaim != user.TokenVersion.ToString())
                {
                    context.Fail("Token version mismatch (revoked)");
                }
            }
        };
    }
}
