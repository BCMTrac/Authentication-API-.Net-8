using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;

namespace AuthenticationAPI.Infrastructure.Filters;

/// <summary>
/// Normalizes all incoming string fields (trim + collapse internal whitespace + Unicode NFKC),
/// enforces payload size limits, rejects control characters, and enforces additionalProperties=false
/// by detecting unknown JSON fields via JsonExtensionData in DTO base type.
/// </summary>
public sealed class InputNormalizationFilter : IActionFilter
{
    private readonly long _maxBodyBytes;
    private static readonly Regex CollapseWs = new Regex("\\s+", RegexOptions.Compiled);

    public InputNormalizationFilter(IConfiguration configuration)
    {
        _maxBodyBytes = configuration.GetValue<long>("Validation:MaxPayloadSizeBytes", 20 * 1024); // Default to 20 KB
    }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        // Guard request size via Content-Length when present; if not present, stream length may be unknown.
        if (context.HttpContext.Request.ContentLength.HasValue)
        {
            if (context.HttpContext.Request.ContentLength.Value > _maxBodyBytes)
            {
                context.Result = new StatusCodeResult(StatusCodes.Status413PayloadTooLarge);
                return;
            }
        }

        try
        {
            // Normalize and validate all string arguments recursively
            foreach (var key in context.ActionArguments.Keys.ToList())
            {
                var value = context.ActionArguments[key];
                if (value is null) continue;
                var normalized = NormalizeObject(value, propertyPath: key);
                context.ActionArguments[key] = normalized;
            }
        }
        catch (ValidationException vex)
        {
            var problem = new ValidationProblemDetails
            {
                Title = "Validation failed",
                Detail = vex.Message,
                Status = StatusCodes.Status400BadRequest,
                Instance = context.HttpContext.Request.Path
            };
            context.Result = new ObjectResult(problem) { StatusCode = problem.Status };
            return;
        }

        // Enforce additionalProperties=false: if any DTO carries extension data, reject
        foreach (var arg in context.ActionArguments.Values)
        {
            if (arg is null) continue;
            var extra = GetExtensionData(arg);
            if (extra is { Count: > 0 })
            {
                var problem = new ValidationProblemDetails
                {
                    Title = "Unexpected fields present",
                    Status = StatusCodes.Status400BadRequest,
                    Detail = "The request contained properties that are not allowed.",
                    Instance = context.HttpContext.Request.Path
                };
                // Add field names into errors for visibility
                problem.Errors.Add("additionalProperties", extra.Keys.ToArray());
                context.Result = new ObjectResult(problem) { StatusCode = problem.Status };
                return;
            }
        }
    }

    public void OnActionExecuted(ActionExecutedContext context) { }

    private static object NormalizeObject(object obj, string propertyPath)
    {
        if (obj is string s)
        {
            return NormalizeString(s, propertyPath);
        }

        var t = obj.GetType();
        // Avoid normalizing framework primitives/structs
        if (t.IsPrimitive || t.IsEnum)
            return obj;

        if (obj is IEnumerable<object?> enumerable)
        {
            var list = new List<object?>();
            int idx = 0;
            foreach (var item in enumerable)
            {
                if (item is null) { list.Add(null); continue; }
                list.Add(NormalizeObject(item, propertyPath + $