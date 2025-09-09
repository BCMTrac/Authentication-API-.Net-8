using System.Net; 
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Infrastructure.Middleware;

public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            var correlationId = context.Items.ContainsKey("X-Correlation-ID") ? context.Items["X-Correlation-ID"]?.ToString() : null;
            _logger.LogError(ex, "Unhandled exception (CorrelationId={CorrelationId})", correlationId);

            var problem = new ProblemDetails
            {
                Title = "An unexpected error occurred",
                Status = (int)HttpStatusCode.InternalServerError,
                Detail = "Please contact support.",
                Instance = context.Request.Path,
                Type = "https://tools.ietf.org/html/rfc7231#section-6.6.1"
            };
            if (!string.IsNullOrWhiteSpace(correlationId))
            {
                problem.Extensions["correlationId"] = correlationId;
            }
            context.Response.StatusCode = problem.Status.Value;
            context.Response.ContentType = "application/problem+json";
            var json = JsonSerializer.Serialize(problem, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            await context.Response.WriteAsync(json);
        }
    }

    // No environment-based error detail in production
}

public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandling(this IApplicationBuilder app) => app.UseMiddleware<ExceptionHandlingMiddleware>();
}
