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
    [Authorize]
    public IActionResult RolesSelect()
    {
        if (!User.Identity?.IsAuthenticated ?? true) return Redirect("/login");
        var roles = User.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).Distinct().ToArray();
        var vm = new RoleSelectionViewModel { AvailableRoles = roles };        
        return View("~/Views/Ui/Roles-Select.cshtml", vm);
    }

    [HttpPost("/roles-select")]
    [Authorize]
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
    [Authorize]
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
    [Authorize]
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
    public IActionResult SiteAdmin() => View("~/Views/Ui/SiteAdmin.cshtml", new SiteAdminLoginViewModel());

    [HttpPost("/site-admin")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SiteAdminPost(SiteAdminLoginViewModel model)
    {
        if (!ModelState.IsValid) return View("~/Views/Ui/SiteAdmin.cshtml", model);
        var user = await _userManager.FindByNameAsync(model.Username) ?? await _userManager.FindByEmailAsync(model.Username);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            return View("~/Views/Ui/SiteAdmin.cshtml", model);
        }
        // Potential extra restriction: ensure user has SiteAdmin role/claim if required
        var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            return View("~/Views/Ui/SiteAdmin.cshtml", model);
        }
        HttpContext.Session.Clear();
        return Redirect("/roles-select");
    }

    [HttpPost("/logout")]
    [ValidateAntiForgeryToken]
    [Authorize]
    public async Task<IActionResult> LogoutPost()
    {
        await _signInManager.SignOutAsync();
        HttpContext.Session.Clear();
        return Redirect("/login");
    }

    [HttpGet("/logout")]
    [Authorize]
    public IActionResult Logout()
    {
        // Simple auto-post form to enforce anti-forgery
        return View("~/Views/Ui/Logout.cshtml");
    }
     
    
}
