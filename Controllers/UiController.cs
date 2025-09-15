using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;

namespace AuthenticationAPI.Controllers;

// Serves production-ready views (login, admin, email confirm, reset password)
[ApiExplorerSettings(IgnoreApi = true)]
public class UiController : Controller
{
    private readonly IWebHostEnvironment _env;
    public UiController(IWebHostEnvironment env) { _env = env; }

    [HttpGet("/")]
    public IActionResult Index() => View();

    [HttpGet("/admin")]
    public IActionResult Admin() => View();

    [HttpGet("/email-confirm")]
    public IActionResult EmailConfirm() => View();

    [HttpGet("/reset-password")]
    public IActionResult ResetPassword() => View();

    // Serve JS/CSS from Assets via controller 
    // Static assets are served from wwwroot via UseStaticFiles (standard ASP.NET Core)
}
