using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using AuthenticationAPI.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using AuthenticationAPI.Models;
using AuthenticationAPI.Infrastructure.Filters;

namespace AuthenticationAPI.Controllers;


[ApiExplorerSettings(IgnoreApi = true)]
public class UiController : Controller
{
    private readonly IWebHostEnvironment _env;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    public UiController(IWebHostEnvironment env, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    { _env = env; _signInManager = signInManager; _userManager = userManager; }

    [HttpGet("/")]
    public IActionResult Index() => Redirect("/login");

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

    [HttpGet("/login")]
    [AllowAnonymous]
    public IActionResult Login() => View("~/Views/Ui/Login.cshtml", new LoginViewModel());

    [HttpPost("/login")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginPost(LoginViewModel model, string? returnUrl = null)
    {
        if (!ModelState.IsValid) return View("~/Views/Ui/Login.cshtml", model);
        var user = await _userManager.FindByNameAsync(model.Username) ?? await _userManager.FindByEmailAsync(model.Username);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            return View("~/Views/Ui/Login.cshtml", model);
        }
        if (await _userManager.IsLockedOutAsync(user))
        {
            ModelState.AddModelError(string.Empty, "Account locked. Try later.");
            return View("~/Views/Ui/Login.cshtml", model);
        }
        var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            return View("~/Views/Ui/Login.cshtml", model);
        }
        HttpContext.Session.Remove(SessionKeys.RoleSelected);
        HttpContext.Session.Remove(SessionKeys.SchemeSelected);
        return Redirect(returnUrl ?? "/roles-select");
    }

    [HttpGet("/roles-select")]
    public IActionResult RolesSelect()
    {
        if (!User.Identity?.IsAuthenticated ?? true) return Redirect("/login");
        var roles = User.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).Distinct().ToArray();
        var vm = new RoleSelectionViewModel { AvailableRoles = roles };        
        return View("~/Views/Ui/Roles-Select.cshtml", vm);
    }

    [HttpPost("/roles-select")]
    [ValidateAntiForgeryToken]
    public IActionResult RolesSelectPost(RoleSelectionViewModel model)
    {
        if (!User.Identity?.IsAuthenticated ?? true) return Redirect("/login");
        var roles = User.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).Distinct().ToHashSet();
        if (!ModelState.IsValid || model.SelectedRole == null || !roles.Contains(model.SelectedRole))
        {
            model.AvailableRoles = roles.ToArray();
            if (model.SelectedRole != null && !roles.Contains(model.SelectedRole)) ModelState.AddModelError("SelectedRole", "Invalid role");
            return View("~/Views/Ui/Roles-Select.cshtml", model);
        }
        HttpContext.Session.SetString(SessionKeys.RoleSelected, model.SelectedRole);
        return Redirect("/schemes-select");
    }

    [HttpGet("/schemes-select")]
    [StepRequirement(RequireRole = true)]
    public IActionResult SchemesSelect()
    {
        var selectedRole = HttpContext.Session.GetString(SessionKeys.RoleSelected);
        if (string.IsNullOrWhiteSpace(selectedRole)) return Redirect("/roles-select");
        // Placeholder schemes - replace with service call
        var schemes = new[] {
            new SchemeItem("1","Example Scheme A","Company"),
            new SchemeItem("2","Example Scheme B","HOA")
        };
        var vm = new SchemeSelectionViewModel { AvailableSchemes = schemes };
        return View("~/Views/Ui/Schemes-Select.cshtml", vm);
    }

    [HttpPost("/schemes-select")]
    [ValidateAntiForgeryToken]
    [StepRequirement(RequireRole = true)]
    public IActionResult SchemesSelectPost(SchemeSelectionViewModel model)
    {
        var schemes = new[] {
            new SchemeItem("1","Example Scheme A","Company"),
            new SchemeItem("2","Example Scheme B","HOA")
        };
        if (!ModelState.IsValid || model.SelectedSchemeId == null || !schemes.Any(s => s.Id == model.SelectedSchemeId))
        {
            model.AvailableSchemes = schemes;
            if (model.SelectedSchemeId != null && !schemes.Any(s => s.Id == model.SelectedSchemeId)) ModelState.AddModelError("SelectedSchemeId", "Invalid scheme");
            return View("~/Views/Ui/Schemes-Select.cshtml", model);
        }
        HttpContext.Session.SetString(SessionKeys.SchemeSelected, model.SelectedSchemeId);
        return Redirect("/");
    }

    [HttpGet("/site-admin")]
    [AllowAnonymous]
    public IActionResult SiteAdmin() => View("~/Views/Ui/SiteAdmin.cshtml");

     
    
}
