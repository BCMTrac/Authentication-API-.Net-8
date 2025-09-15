using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers;

// Serves production-ready views (login, admin, email confirm, reset password)
[ApiExplorerSettings(IgnoreApi = true)]
public class UiController : Controller
{
    [HttpGet("/")]
    public IActionResult Index() => View();

    [HttpGet("/admin")]
    public IActionResult Admin() => View();

    [HttpGet("/email-confirm")]
    public IActionResult EmailConfirm() => View();

    [HttpGet("/reset-password")]
    public IActionResult ResetPassword() => View();
}

