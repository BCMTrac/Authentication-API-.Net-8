using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/admin")]
[ApiController]
[Authorize(Roles = "Admin")]
public partial class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly ISessionService _sessions;
    private readonly IEmailSender _email;
    private readonly IEmailTemplateRenderer _templates;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<AdminController> _logger;
    private readonly IAuditService _auditService;

    public AdminController(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext db,
        ISessionService sessions,
        IEmailSender email,
        IEmailTemplateRenderer templates,
        RoleManager<IdentityRole> roleManager,
        ILogger<AdminController> logger,
        IAuditService auditService)
    {
        _userManager = userManager;
        _db = db;
        _sessions = sessions;
        _email = email;
        _templates = templates;
        _roleManager = roleManager;
        _logger = logger;
        _auditService = auditService;
    }

    [HttpGet("users/search")]
    [ProducesResponseType(typeof(IEnumerable<UserSummaryDto>), 200)]
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
            .Select(u => new UserSummaryDto(u.Id, u.UserName, u.Email, u.EmailConfirmed, u.LockoutEnd, u.MfaEnabled))
            .ToListAsync();
        return Ok(users);
    }

    [HttpGet("users/{id}")]
    [ProducesResponseType(typeof(UserDetailDto), 200)]
    [ProducesResponseType(404)]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        var roles = await _userManager.GetRolesAsync(user);
        var dto = new UserDetailDto(user.Id, user.UserName, user.Email, user.EmailConfirmed, user.PhoneNumber, user.FullName, user.LockoutEnd, user.MfaEnabled, roles);
        return Ok(dto);
    }

    [HttpPost("users/{id}/roles/add")]
    public async Task<IActionResult> AddRole(string id, [FromBody] RoleDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Role)) throw new BadRequestException("Role name is required.");
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();

        if (!await _roleManager.RoleExistsAsync(dto.Role))
        {
            _logger.LogInformation("Creating new role: {RoleName}", dto.Role);
            var createResult = await _roleManager.CreateAsync(new IdentityRole(dto.Role));
            if (!createResult.Succeeded)
            {
                _logger.LogError("Failed to create role {RoleName}. Errors: {Errors}", dto.Role, createResult.Errors.Select(e => e.Description));
                throw new RoleCreationException(string.Join(", ", createResult.Errors.Select(e => e.Description)));
            }
        }

        var result = await _userManager.AddToRoleAsync(user, dto.Role);
        if (result.Succeeded)
        {
            await _auditService.LogAsync("UserRoleAdded", nameof(ApplicationUser), user.Id, new { Role = dto.Role });
            return Ok();
        }
        
        _logger.LogError("Failed to add user {UserId} to role {RoleName}. Errors: {Errors}", id, dto.Role, result.Errors.Select(e => e.Description));
        throw new BadRequestException($"Failed to add role. {string.Join(", ", result.Errors.Select(e => e.Description))}");
    }

    [HttpPost("users/{id}/roles/remove")]
    public async Task<IActionResult> RemoveRole(string id, [FromBody] RoleDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Role)) throw new BadRequestException("Role name is required.");
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        var res = await _userManager.RemoveFromRoleAsync(user, dto.Role);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserRoleRemoved", nameof(ApplicationUser), user.Id, new { Role = dto.Role });
            return Ok();
        }
        throw new BadRequestException($"Failed to remove role. {string.Join(", ", res.Errors.Select(e => e.Description))}");
    }

    [HttpPost("users/{id}/email/confirm")]
    public async Task<IActionResult> ForceConfirmEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        if (user.EmailConfirmed) return Ok(new EmailConfirmedResponse { EmailConfirmed = true });
        user.EmailConfirmed = true;
        var res = await _userManager.UpdateAsync(user);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserEmailConfirmed", nameof(ApplicationUser), user.Id);
            return Ok(new EmailConfirmedResponse { EmailConfirmed = true });
        }
        throw new BadRequestException("Failed to confirm email.");
    }

    [HttpPost("users/{id}/email/resend-confirm")]
    public async Task<IActionResult> ResendConfirmEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || string.IsNullOrWhiteSpace(user.Email)) throw new UserNotFoundException("User or user email not found.");
        try
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var config = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var confirmUrlBase = config["Email:EmailConfirm:Url"] ?? string.Empty;
            string? link = string.IsNullOrWhiteSpace(confirmUrlBase) ? null : $"{confirmUrlBase}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
            var (html, _) = await _templates.RenderAsync("email-confirm", new Dictionary<string,string>
            {
                ["Title"] = "Confirm your email",
                ["Intro"] = "Please confirm your email to activate the account.",
                ["ActionText"] = "Confirm Email",
                ["ActionUrl"] = link ?? string.Empty,
                ["Token"] = link == null ? token : string.Empty
            });
            _email.QueueSendAsync(user.Email!, "Email confirmation", html);
            await _auditService.LogAsync("UserEmailConfirmResent", nameof(ApplicationUser), user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to queue resend confirmation email for user {UserId}", id);
            throw new BadRequestException("An internal error occurred while queuing the email.");
        }
        return Ok(new SentResponse { Sent = true });
    }

    [HttpPost("users/{id}/mfa/disable")]
    public async Task<IActionResult> AdminDisableMfa(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        user.MfaEnabled = false;
        user.MfaSecret = null;
        user.MfaLastTimeStep = -1;
        var codes = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
        _db.UserRecoveryCodes.RemoveRange(codes);
        await _db.SaveChangesAsync();
        var res = await _userManager.UpdateAsync(user);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserMfaDisabled", nameof(ApplicationUser), user.Id);
            return Ok();
        }
        throw new BadRequestException("Failed to disable MFA.");
    }

    [HttpPost("users/{id}/password/reset-email")]
    public async Task<IActionResult> SendPasswordResetEmail(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null || string.IsNullOrWhiteSpace(user.Email)) throw new UserNotFoundException("User or user email not found.");
        try
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var config = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var resetUrl = config["PasswordReset:Url"];
            string? link = string.IsNullOrWhiteSpace(resetUrl) ? null : $"{resetUrl}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
            var (html, _) = await _templates.RenderAsync("password-reset", new Dictionary<string,string>
            {
                ["Title"] = "Reset your password",
                ["Intro"] = "We received a request to reset your password. If you didn't request this, you can ignore this email.",
                ["ActionText"] = "Reset Password",
                ["ActionUrl"] = link ?? string.Empty,
                ["Token"] = link == null ? token : string.Empty
            });
            _email.QueueSendAsync(user.Email!, "Password reset", html);
            await _auditService.LogAsync("UserPasswordResetEmailSent", nameof(ApplicationUser), user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to queue password reset email for user {UserId}", id);
            throw new BadRequestException("An internal error occurred while queuing the email.");
        }
        return Ok(new SentResponse { Sent = true });
    }

    [HttpPost("users/{id}/password/set-temporary")]
    public async Task<IActionResult> SetTemporaryPassword(string id, [FromBody] TempPasswordDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.NewPassword)) throw new BadRequestException("New password is required.");
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var res = await _userManager.ResetPasswordAsync(user, token, dto.NewPassword);
        if (res.Succeeded)
        {
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _sessions.RevokeAllForUserAsync(user.Id, "admin-temp-password");
            await _auditService.LogAsync("UserTemporaryPasswordSet", nameof(ApplicationUser), user.Id);
            return Ok();
        }
        throw new BadRequestException(string.Join(", ", res.Errors.Select(e => e.Description)));
    }

    [HttpPost("users/{id}/sessions/revoke-all")]
    public async Task<IActionResult> RevokeAllSessions(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        await _sessions.RevokeAllForUserAsync(user.Id, "admin-revoke-all");
        await _auditService.LogAsync("UserAllSessionsRevoked", nameof(ApplicationUser), user.Id);
        return Ok();
    }

    [HttpPost("users/{id}/bump-token-version")]
    public async Task<IActionResult> BumpTokenVersion(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        user.TokenVersion += 1;
        var res = await _userManager.UpdateAsync(user);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserTokenVersionBumped", nameof(ApplicationUser), user.Id);
            return Ok(new { user.Id, user.TokenVersion });
        }
        throw new BadRequestException(string.Join(", ", res.Errors.Select(e => e.Description)));
    }

    [HttpGet("users/{id}/sessions")]
    [ProducesResponseType(typeof(IEnumerable<SessionDto>), 200)]
    public async Task<IActionResult> ListSessions(string id)
    {
        var sessions = await _db.Sessions.Where(s => s.UserId == id)
            .OrderByDescending(s => s.CreatedUtc)
            .Select(s => new SessionDto(s.Id, s.CreatedUtc, s.LastSeenUtc, s.RevokedAtUtc, s.Ip, s.UserAgent))
            .ToListAsync();
        return Ok(sessions);
    }

    [HttpPost("users/{id}/sessions/{sessionId}/revoke")]
    public async Task<IActionResult> RevokeSession(string id, Guid sessionId)
    {
        var session = await _db.Sessions.FindAsync(sessionId);
        if (session == null || session.UserId != id) throw new NotFoundException("Session not found for this user.");
        await _sessions.RevokeAsync(sessionId, "admin-revoke");
        await _auditService.LogAsync("UserSessionRevoked", nameof(ApplicationUser), id, new { SessionId = sessionId });
        return Ok();
    }

    [HttpPost("users/{id}/lock")]
    public async Task<IActionResult> LockUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        user.LockoutEnabled = true;
        user.LockoutEnd = DateTimeOffset.MaxValue;
        var res = await _userManager.UpdateAsync(user);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserLocked", nameof(ApplicationUser), user.Id);
            return Ok();
        }
        throw new BadRequestException("Failed to lock user.");
    }

    [HttpPost("users/{id}/unlock")]
    public async Task<IActionResult> UnlockUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) throw new UserNotFoundException();
        user.LockoutEnd = null;
        var res = await _userManager.UpdateAsync(user);
        if (res.Succeeded)
        {
            await _auditService.LogAsync("UserUnlocked", nameof(ApplicationUser), user.Id);
            return Ok();
        }
        throw new BadRequestException("Failed to unlock user.");
    }

    [HttpPost("test-email")]
    public IActionResult SendTestEmail([FromBody] TestEmailDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.To)) throw new BadRequestException("Recipient email is required.");
        string subject = string.IsNullOrWhiteSpace(dto.Subject) ? "Test Email" : dto.Subject!;
        string body = string.IsNullOrWhiteSpace(dto.Body) ? "Hello from AuthenticationAPI" : dto.Body!;
        _email.QueueSendAsync(dto.To, subject, body);
        return Ok(new SentResponse { Sent = true });
    }
}