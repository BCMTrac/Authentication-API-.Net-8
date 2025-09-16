using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;

namespace AuthenticationAPI.Controllers;


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

    [HttpGet("/activate")]
    public IActionResult Activate() => View();

    [Authorize(Roles = "Admin")]
    [HttpGet("/ui/onboarding")]
    public IActionResult Onboarding() => View();

    [HttpGet("/admin-login")]
    public IActionResult AdminLogin() => View();

    [HttpGet("/settings")]
    [Authorize]
    public IActionResult Settings() => View();

     
    
}
