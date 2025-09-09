using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Email;
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
    private readonly IEmailTemplateRenderer _templates;
    public AdminController(
        UserManager<ApplicationUser> userManager,
        AuthenticationAPI.Data.ApplicationDbContext db,
        ISessionService sessions,
        AuthenticationAPI.Services.Email.IEmailSender email,
        IEmailTemplateRenderer templates)
    {
        _userManager = userManager;
        _db = db;
        _sessions = sessions;
        _email = email;
        _templates = templates;
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

    [HttpPost("test-email")]
    public async Task<IActionResult> SendTestEmail([FromBody] TestEmailDto dto)
    {
        if (dto == null || string.IsNullOrWhiteSpace(dto.To)) return BadRequest();
        string subject = string.IsNullOrWhiteSpace(dto.Subject) ? "Test Email" : dto.Subject!;
        string body = string.IsNullOrWhiteSpace(dto.Body) ? "Hello from AuthenticationAPI" : dto.Body!;
        await _email.SendAsync(dto.To!, subject, body);
        return Ok(new { sent = true });
    }
}

public class TestEmailDto
{
    public string? To { get; set; }
    public string? Subject { get; set; }
    public string? Body { get; set; }
}

