using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using AuthenticationAPI.Exceptions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

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
        catch (ApiException ex)
        {
            _logger.LogWarning("API Exception: {Message} (StatusCode: {StatusCode})", ex.Message, ex.StatusCode);
            await HandleApiExceptionAsync(context, ex);
        }
        catch (Exception ex)
        {
            var correlationId = context.TraceIdentifier;
            _logger.LogError(ex, "Unhandled exception (CorrelationId={CorrelationId})", correlationId);
            await HandleGenericExceptionAsync(context, correlationId);
        }
    }

    private static Task HandleApiExceptionAsync(HttpContext context, ApiException exception)
    {
        var problem = new ProblemDetails
        {
            Title = "An error occurred",
            Status = exception.StatusCode,
            Detail = exception.Message,
            Instance = context.Request.Path
        };

        context.Response.StatusCode = problem.Status.Value;
        context.Response.ContentType = "application/problem+json";
        return context.Response.WriteAsync(JsonSerializer.Serialize(problem));
    }

    private static Task HandleGenericExceptionAsync(HttpContext context, string correlationId)
    {
        var problem = new ProblemDetails
        {
            Title = "An unexpected internal error occurred",
            Status = (int)HttpStatusCode.InternalServerError,
            Detail = "The service encountered an error. Please contact support and provide the correlation ID.",
            Instance = context.Request.Path,
            Type = "https://tools.ietf.org/html/rfc7231#section-6.6.1"
        };
        problem.Extensions["correlationId"] = correlationId;

        context.Response.StatusCode = problem.Status.Value;
        context.Response.ContentType = "application/problem+json";
        return context.Response.WriteAsync(JsonSerializer.Serialize(problem));
    }
}

public static class ExceptionHandlingMiddlewareExtensions
{
    public static IApplicationBuilder UseGlobalExceptionHandling(this IApplicationBuilder app) => app.UseMiddleware<ExceptionHandlingMiddleware>();
}