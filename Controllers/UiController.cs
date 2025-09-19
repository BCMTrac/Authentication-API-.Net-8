using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using AuthenticationAPI.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using AuthenticationAPI.Models;
using AuthenticationAPI.Infrastructure.Filters;
using AuthenticationAPI.Services;
using AuthenticationAPI.Models.Options;
using AuthenticationAPI.Infrastructure.Security;

namespace AuthenticationAPI.Controllers;


[ApiExplorerSettings(IgnoreApi = true)]
public class UiController : Controller
{
    private readonly IWebHostEnvironment _env;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILegacyAccessService _legacy;
    private readonly BridgeOptions _bridge;
    private readonly ISessionService _sessions;
    private readonly IServiceProvider _sp;
    public UiController(IWebHostEnvironment env, SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILegacyAccessService legacy, Microsoft.Extensions.Options.IOptions<BridgeOptions> bridge, ISessionService sessions, IServiceProvider sp)
    { _env = env; _signInManager = signInManager; _userManager = userManager; _legacy = legacy; _bridge = bridge.Value; _sessions = sessions; _sp = sp; }

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
    public async Task<IActionResult> RolesSelect()
    {
        if (!User.Identity?.IsAuthenticated ?? true) return Redirect("/login");
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Redirect("/login");
        var roles = await _legacy.GetRolesForUserAsync(user);
        var vm = new RoleSelectionViewModel { AvailableRoles = roles };        
        return View("~/Views/Ui/Roles-Select.cshtml", vm);
    }

    [HttpPost("/roles-select")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RolesSelectPost(RoleSelectionViewModel model)
    {
        if (!User.Identity?.IsAuthenticated ?? true) return Redirect("/login");
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Redirect("/login");
        var roles = (await _legacy.GetRolesForUserAsync(user)).ToHashSet();
        if (!ModelState.IsValid || model.SelectedRole == null || !roles.Contains(model.SelectedRole))
        {
            model.AvailableRoles = roles.ToArray();
            if (model.SelectedRole != null && !roles.Contains(model.SelectedRole)) ModelState.AddModelError("SelectedRole", "Invalid role");
            return View("~/Views/Ui/Roles-Select.cshtml", model);
        }
        HttpContext.Session.SetString(SessionKeys.RoleSelected, model.SelectedRole);
        if (_bridge.Enabled)
        {
            // Use Identity session id if exists; otherwise create a session record to back headers
            var sidClaim = User.Claims.FirstOrDefault(c => c.Type == AuthConstants.ClaimTypes.SessionId)?.Value;
            Guid sid;
            if (!Guid.TryParse(sidClaim, out sid))
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var ua = Request.Headers["User-Agent"].ToString();
                var session = await _sessions.CreateAsync(user, ip, ua);
                sid = session.Id;
            }
            _legacy.EmitLegacyHeaders(Response, _bridge, sid);
            // Set explicit legacy cookies for session id and clear scheme/access cookies at this stage
            Response.Cookies.Append(_bridge.AdminBackOfficeCookieName, sid.ToString(), new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None });
            Response.Cookies.Delete(_bridge.SchemeCookieName);
            Response.Cookies.Delete(_bridge.AccessRightsCookieName);
        }
        return Redirect("/schemes-select");
    }

    [HttpGet("/schemes-select")]
    [Authorize]
    [StepRequirement(RequireRole = true)]
    public async Task<IActionResult> SchemesSelect()
    {
        var selectedRole = HttpContext.Session.GetString(SessionKeys.RoleSelected);
        if (string.IsNullOrWhiteSpace(selectedRole)) return Redirect("/roles-select");
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Redirect("/login");
        var schemes = await _legacy.GetSchemesForAsync(user, selectedRole);
        var vm = new SchemeSelectionViewModel { AvailableSchemes = schemes };
        return View("~/Views/Ui/Schemes-Select.cshtml", vm);
    }

    [HttpPost("/schemes-select")]
    [ValidateAntiForgeryToken]
    [Authorize]
    [StepRequirement(RequireRole = true)]
    public async Task<IActionResult> SchemesSelectPost(SchemeSelectionViewModel model)
    {
        var selectedRole = HttpContext.Session.GetString(SessionKeys.RoleSelected) ?? string.Empty;
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Redirect("/login");
        var schemes = await _legacy.GetSchemesForAsync(user, selectedRole);
        if (!ModelState.IsValid || model.SelectedSchemeId == null || !schemes.Any(s => s.Id == model.SelectedSchemeId))
        {
            model.AvailableSchemes = schemes;
            if (model.SelectedSchemeId != null && !schemes.Any(s => s.Id == model.SelectedSchemeId)) ModelState.AddModelError("SelectedSchemeId", "Invalid scheme");
            return View("~/Views/Ui/Schemes-Select.cshtml", model);
        }
        HttpContext.Session.SetString(SessionKeys.SchemeSelected, model.SelectedSchemeId);
        // Emit legacy headers and UI JWT with selected role/scheme for YARP if enabled
        if (_bridge.Enabled)
        {
            var sidClaim = User.Claims.FirstOrDefault(c => c.Type == AuthConstants.ClaimTypes.SessionId)?.Value;
            Guid sid;
            if (!Guid.TryParse(sidClaim, out sid))
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var ua = Request.Headers["User-Agent"].ToString();
                var session = await _sessions.CreateAsync(user, ip, ua);
                sid = session.Id;
            }
            _legacy.EmitLegacyHeaders(Response, _bridge, sid);
            // Set AdminBackOffcieCookie to session id
            Response.Cookies.Append(_bridge.AdminBackOfficeCookieName, sid.ToString(), new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None });
            // Set SchemeCookie to selected scheme id
            Response.Cookies.Append(_bridge.SchemeCookieName, model.SelectedSchemeId, new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.None });
            // Build and set UserAccessRights cookie (serialized rights string)
            var rights = await _legacy.GetAccessRightsCookieValueAsync(user, selectedRole, model.SelectedSchemeId);
            Response.Cookies.Append(_bridge.AccessRightsCookieName, rights, new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.None });
            if (!string.IsNullOrWhiteSpace(_bridge.JwtHeaderName))
            {
                var jwt = await _legacy.IssueUiJwtAsync(user, selectedRole, model.SelectedSchemeId, _sp);
                Response.Headers[_bridge.JwtHeaderName] = jwt;
                if (!string.IsNullOrWhiteSpace(_bridge.JwtCookieName))
                {
                    Response.Cookies.Append(_bridge.JwtCookieName!, jwt, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None });
                }
            }
        }
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
        // Set SiteAdmin cookie and emit legacy headers/cookies for back-office access
        if (_bridge.Enabled)
        {
            var sidClaim = User.Claims.FirstOrDefault(c => c.Type == AuthConstants.ClaimTypes.SessionId)?.Value;
            Guid sid;
            if (!Guid.TryParse(sidClaim, out sid))
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var ua = Request.Headers["User-Agent"].ToString();
                var session = await _sessions.CreateAsync(user, ip, ua);
                sid = session.Id;
            }
            _legacy.EmitLegacyHeaders(Response, _bridge, sid);
            Response.Cookies.Append(_bridge.AdminBackOfficeCookieName, sid.ToString(), new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None });
            var saCookie = await _legacy.GetSiteAdminCookieAsync(user);
            if (!string.IsNullOrWhiteSpace(saCookie))
            {
                var cookieVal = string.IsNullOrWhiteSpace(_bridge.SiteAdminCookieKey)
                    ? saCookie
                    : $"{_bridge.SiteAdminCookieKey}={saCookie}";
                Response.Cookies.Append(_bridge.SiteAdminCookieName, cookieVal, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None });
            }
        }
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

    [HttpGet("/newLogin")]
    [AllowAnonymous]
    public IActionResult NewLogin() => View("~/Views/Ui/newLogin.cshtml", new LoginViewModel());
}
