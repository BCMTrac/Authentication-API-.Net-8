using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Controllers;

[Route("api/v1/users")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _db;
    public UsersController(UserManager<ApplicationUser> userManager, ApplicationDbContext db)
    { _userManager = userManager; _db = db; }

    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = "Identity.Application,Bearer")]
    public async Task<IActionResult> Me()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();
        var roles = await _userManager.GetRolesAsync(user);
        var sessionCount = await _db.Sessions.CountAsync(s => s.UserId == user.Id);
        return Ok(new
        {
            user.Id,
            user.UserName,
            user.Email,
            user.EmailConfirmed,
            user.MfaEnabled,
            roles,
            sessionCount
        });
    }
}
