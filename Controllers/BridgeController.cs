using System.Security.Claims;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/bridge")]
[ApiController]
public sealed class BridgeController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly AppDbContext _appDb;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly BridgeOptions _bridge;

    public BridgeController(
        ApplicationDbContext db,
        AppDbContext appDb,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        Microsoft.Extensions.Options.IOptions<BridgeOptions> bridge)
    {
        _db = db; _appDb = appDb; _userManager = userManager; _roleManager = roleManager; _bridge = bridge.Value;
    }

    private bool AuthorizeBridge()
    {
        if (!_bridge.Enabled) return false;
        if (string.IsNullOrWhiteSpace(_bridge.ApiKey)) return false;
        if (!Request.Headers.TryGetValue(_bridge.ApiKeyHeader, out var provided)) return false;
        return string.Equals(provided.ToString(), _bridge.ApiKey, StringComparison.Ordinal);
    }

    public sealed class SessionInfo
    {
        public required string SessionId { get; set; }
        public required string UserId { get; set; }
        public required string UserName { get; set; }
        public string? Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool MfaEnabled { get; set; }
        public string[] Roles { get; set; } = Array.Empty<string>();
        public string[] Scopes { get; set; } = Array.Empty<string>();
    }

    [HttpGet("session/{sid}")]
    public async Task<IActionResult> GetSession(string sid)
    {
        if (!AuthorizeBridge()) return Forbid();
        if (!Guid.TryParse(sid, out var sessionId)) return BadRequest();
        var session = await _db.Sessions.Include(s => s.User).FirstOrDefaultAsync(s => s.Id == sessionId && s.RevokedAtUtc == null);
        if (session == null || session.User == null) return NotFound();
        var user = session.User;
        var roles = await _userManager.GetRolesAsync(user);
        var roleIds = await _roleManager.Roles.Where(r => roles.Contains(r.Name!)).Select(r => r.Id).ToListAsync();
        var scopes = await _appDb.RolePermissions.Where(rp => roleIds.Contains(rp.RoleId)).Include(rp => rp.Permission)
            .Select(rp => rp.Permission!.Name).Distinct().ToArrayAsync();
        var dto = new SessionInfo
        {
            SessionId = session.Id.ToString(),
            UserId = user.Id,
            UserName = user.UserName!,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            MfaEnabled = user.MfaEnabled,
            Roles = roles.ToArray(),
            Scopes = scopes
        };
        return Ok(dto);
    }
}
