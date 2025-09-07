using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/admin")] 
[ApiController]
[Authorize(Roles = "Admin")] // Require Admin role
public partial class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthenticationAPI.Data.ApplicationDbContext _db;
    private readonly ISessionService _sessions;
    private readonly AuthenticationAPI.Services.Email.IEmailSender _email;
    public AdminController(
        UserManager<ApplicationUser> userManager,
        AuthenticationAPI.Data.ApplicationDbContext db,
        ISessionService sessions,
        AuthenticationAPI.Services.Email.IEmailSender email)
    {
        _userManager = userManager;
        _db = db;
        _sessions = sessions;
        _email = email;
    }

    [HttpPost("users/{id}/bump-token-version")]
    public async Task<IActionResult> BumpTokenVersion(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        user.TokenVersion += 1;
        var res = await _userManager.UpdateAsync(user);
        if (!res.Succeeded)
        {
            var pd = new Microsoft.AspNetCore.Mvc.ProblemDetails
            {
                Title = "Failed to update user token version",
                Status = 500,
                Detail = "UpdateAsync returned errors"
            };
            pd.Extensions["errors"] = res.Errors.Select(e => e.Description).ToArray();
            return StatusCode(500, pd);
        }
        return Ok(new { user.Id, user.TokenVersion });
    }

    [HttpGet("users/{id}/sessions")]
    public IActionResult ListSessions(string id)
    {
        var sessions = _db.Sessions.Where(s => s.UserId == id)
            .OrderByDescending(s => s.CreatedUtc)
            .Select(s => new { s.Id, s.CreatedUtc, s.LastSeenUtc, s.RevokedAtUtc, s.Ip, s.UserAgent })
            .ToList();
        return Ok(sessions);
    }

    [HttpPost("users/{id}/sessions/{sessionId}/revoke")]
    public async Task<IActionResult> RevokeSession(string id, Guid sessionId)
    {
        var session = await _db.Sessions.FindAsync(sessionId);
        if (session == null || session.UserId != id) return NotFound();
        await _sessions.RevokeAsync(sessionId, "admin-revoke");
        return Ok();
    }

    [HttpPost("users/{id}/lock")]
    public async Task<IActionResult> LockUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        user.LockoutEnabled = true;
        user.LockoutEnd = DateTimeOffset.MaxValue;
        var res = await _userManager.UpdateAsync(user);
        return res.Succeeded ? Ok() : StatusCode(500, new { error = "Failed to lock user" });
    }

    [HttpPost("users/{id}/unlock")]
    public async Task<IActionResult> UnlockUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        user.LockoutEnd = null;
        var res = await _userManager.UpdateAsync(user);
        return res.Succeeded ? Ok() : StatusCode(500, new { error = "Failed to unlock user" });
    }
}

public partial class AdminController
{
    public record TestEmailDto(string To, string Subject, string Body);

    [HttpPost("test-email")]
    public async Task<IActionResult> SendTestEmail([FromBody] TestEmailDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.To)) return BadRequest(new { error = "Missing 'to'" });
        await _email.SendAsync(dto.To, string.IsNullOrWhiteSpace(dto.Subject) ? "Test Email" : dto.Subject, dto.Body ?? "This is a test email from Authentication API.");
        return Ok(new { sent = true });
    }
}
