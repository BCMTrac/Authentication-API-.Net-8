using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

[Route("api/admin")] 
[ApiController]
[Authorize(Roles = "Admin")] // Require Admin role
public class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    public AdminController(UserManager<ApplicationUser> userManager) => _userManager = userManager;

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
}
