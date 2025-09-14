using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Email;
using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
    private readonly RoleManager<IdentityRole> _roleManager;
    public AdminController(
        UserManager<ApplicationUser> userManager,
        AuthenticationAPI.Data.ApplicationDbContext db,
        ISessionService sessions,
        AuthenticationAPI.Services.Email.IEmailSender email,
        IEmailTemplateRenderer templates,
        RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _db = db;
        _sessions = sessions;
        _email = email;
        _templates = templates;
        _roleManager = roleManager;
    }

    [HttpGet("users/search")]
    public async Task<IActionResult> SearchUsers([FromQuery] string? q, [FromQuery] int take = 25)
    {
        take = Math.Clamp(take, 1, 100);
        var query = _userManager.Users.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var term = q.Trim();
            query = query.Where(u => u.UserName!.Contains(term) || (u.Email != null && u.Email.Contains(term)));
        }
        var users = await query
            .OrderBy(u => u.UserName)
            .Take(take)
            .Select(u => new {
                u.Id, u.UserName, u.Email, u.EmailConfirmed, u.LockoutEnd, u.MfaEnabled
            })
            .ToListAsync();
        return Ok(users);
    }

    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new
        {
            user.Id,
            user.UserName,
            user.Email,
            user.EmailConfirmed,
            user.PhoneNumber,
            user.FullName,
            user.LockoutEnd,
            user.MfaEnabled,
            roles
        });
    }

    public record RoleDto(string Role);

    [HttpPost("users/{id}/roles/add")]
    public async Task<IActionResult> AddRole(string id, [FromBody] RoleDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Role)) return BadRequest(new { error = "Role is required" });
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        if (!await _roleManager.RoleExistsAsync(dto.Role))
        {
            var create = await _roleManager.CreateAsync(new IdentityRole(dto.Role));
            if (!create.Succeeded) return StatusCode(500, new { error = "Failed to create role" });
        }
        var res = await _userManager.AddToRoleAsync(user, dto.Role);
        return res.Succeeded ? Ok() : StatusCode(500, new { error = string.Join(", ", res.Errors.Select(e => e.Description)) });
    }

    [HttpPost("users/{id}/roles/remove")]
    public async Task<IActionResult> RemoveRole(string id, [FromBody] RoleDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Role)) return BadRequest(new { error = "Role is required" });
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        var res = await _userManager.RemoveFromRoleAsync(user, dto.Role);
        return res.Succeeded ? Ok() : StatusCode(500, new { error = string.Join(", ", res.Errors.Select(e => e.Description)) });
    }

    [HttpPost("users/{id}/email/confirm")]
    public async Task<IActionResult> ForceConfirmEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        if (user.EmailConfirmed) return Ok(new { emailConfirmed = true });
        user.EmailConfirmed = true;
        var res = await _userManager.UpdateAsync(user);
        return res.Succeeded ? Ok(new { emailConfirmed = true }) : StatusCode(500, new { error = "Failed to confirm email" });
    }

    [HttpPost("users/{id}/email/resend-confirm")]
    public async Task<IActionResult> ResendConfirmEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || string.IsNullOrWhiteSpace(user.Email)) return NotFound();
        try
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var config = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var confirmUrlBase = config["Email:EmailConfirm:Url"] ?? string.Empty;
            string? link = string.IsNullOrWhiteSpace(confirmUrlBase) ? null : $"{confirmUrlBase}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
            var (html, _) = await _templates.RenderAsync("email-confirm", new Dictionary<string,string>
            {
                ["Title"] = "Confirm your email",
                ["Intro"] = "Please confirm your email to activate your account.",
                ["ActionText"] = "Confirm Email",
                ["ActionUrl"] = link ?? string.Empty,
                ["Token"] = link == null ? token : string.Empty
            });
            await _email.SendAsync(user.Email!, "Email confirmation", html);
        }
        catch (Exception)
        {
            return StatusCode(500, new { error = "Failed to send confirmation email" });
        }
        return Ok(new { sent = true });
    }

    [HttpPost("users/{id}/mfa/disable")]
    public async Task<IActionResult> AdminDisableMfa(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        user.MfaEnabled = false;
        user.MfaSecret = null;
        user.MfaLastTimeStep = -1;
        var codes = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
        _db.UserRecoveryCodes.RemoveRange(codes);
        await _db.SaveChangesAsync();
        var res = await _userManager.UpdateAsync(user);
        return res.Succeeded ? Ok() : StatusCode(500, new { error = "Failed to disable MFA" });
    }

    [HttpPost("users/{id}/password/reset-email")]
    public async Task<IActionResult> SendPasswordResetEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || string.IsNullOrWhiteSpace(user.Email)) return NotFound();
        try
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var config = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var resetUrl = config["PasswordReset:Url"];
            string? link = string.IsNullOrWhiteSpace(resetUrl) ? null : $"{resetUrl}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
            var (html, _) = await _templates.RenderAsync("password-reset", new Dictionary<string,string>
            {
                ["Title"] = "Reset your password",
                ["Intro"] = "We received a request to reset your password.",
                ["ActionText"] = "Reset Password",
                ["ActionUrl"] = link ?? string.Empty,
                ["Token"] = link == null ? token : string.Empty
            });
            await _email.SendAsync(user.Email!, "Password reset", html);
        }
        catch (Exception)
        {
            return StatusCode(500, new { error = "Failed to send password reset email" });
        }
        return Ok(new { sent = true });
    }

    public record TempPasswordDto(string NewPassword);
    [HttpPost("users/{id}/password/set-temporary")]
    public async Task<IActionResult> SetTemporaryPassword(string id, [FromBody] TempPasswordDto dto)
    {
        if (dto == null || string.IsNullOrWhiteSpace(dto.NewPassword)) return BadRequest(new { error = "NewPassword is required" });
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var res = await _userManager.ResetPasswordAsync(user, token, dto.NewPassword);
        if (!res.Succeeded) return StatusCode(500, new { error = string.Join(", ", res.Errors.Select(e => e.Description)) });
        user.TokenVersion += 1;
        await _userManager.UpdateAsync(user);
        await _sessions.RevokeAllForUserAsync(user.Id, "admin-temp-password");
        return Ok();
    }

    [HttpPost("users/{id}/sessions/revoke-all")]
    public async Task<IActionResult> RevokeAllSessions(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        await _sessions.RevokeAllForUserAsync(user.Id, "admin-revoke-all");
        return Ok();
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

