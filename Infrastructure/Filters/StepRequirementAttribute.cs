using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Infrastructure.Filters;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class StepRequirementAttribute : ActionFilterAttribute
{
    public bool RequireRole { get; set; }

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var session = context.HttpContext.Session;
        if (RequireRole && string.IsNullOrWhiteSpace(session.GetString("RoleSelected")))
        {
            context.Result = new RedirectResult("/roles-select");
            return;
        }
        base.OnActionExecuting(context);
    }
}