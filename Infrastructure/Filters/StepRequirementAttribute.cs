using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthenticationAPI.Infrastructure.Filters;

public static class SessionKeys
{
    public const string RoleSelected = "FLOW_SELECTED_ROLE";
    public const string SchemeSelected = "FLOW_SELECTED_SCHEME";
}

/// <summary>
/// Enforces that prior steps in the authentication wizard have been satisfied.
/// Use RequireRole or RequireScheme depending on the page.
/// </summary>
public class StepRequirementAttribute : ActionFilterAttribute
{
    public bool RequireRole { get; set; }
    public bool RequireScheme { get; set; }

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var http = context.HttpContext;
        // Must be authenticated for any guarded step
        if (!http.User?.Identity?.IsAuthenticated ?? true)
        {
            context.Result = new RedirectResult("/login");
            return;
        }

        if (RequireRole)
        {
            if (string.IsNullOrWhiteSpace(http.Session.GetString(SessionKeys.RoleSelected)))
            {
                context.Result = new RedirectResult("/roles-select");
                return;
            }
        }
        if (RequireScheme)
        {
            if (string.IsNullOrWhiteSpace(http.Session.GetString(SessionKeys.SchemeSelected)))
            {
                context.Result = new RedirectResult("/schemes-select");
                return;
            }
        }
        base.OnActionExecuting(context);
    }
}