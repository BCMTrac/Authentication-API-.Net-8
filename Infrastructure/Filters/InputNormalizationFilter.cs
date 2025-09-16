using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;

namespace AuthenticationAPI.Infrastructure.Filters;

public sealed class InputNormalizationFilter : IActionFilter
{
    private readonly long _maxBodyBytes;
    private static readonly Regex CollapseWs = new("\\s+", RegexOptions.Compiled);

    public InputNormalizationFilter(IConfiguration configuration)
    {
        _maxBodyBytes = configuration.GetValue<long>("Validation:MaxPayloadSizeBytes", 20 * 1024);
    }

    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (context.HttpContext.Request.ContentLength.HasValue &&
            context.HttpContext.Request.ContentLength.Value > _maxBodyBytes)
        {
            context.Result = new StatusCodeResult(StatusCodes.Status413PayloadTooLarge);
            return;
        }

        try
        {
            foreach (var key in context.ActionArguments.Keys.ToList())
            {
                var value = context.ActionArguments[key];
                if (value is null) continue;
                context.ActionArguments[key] = NormalizeObject(value, key);
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
                problem.Errors.Add("additionalProperties", extra.Keys.ToArray());
                context.Result = new ObjectResult(problem) { StatusCode = problem.Status };
                return;
            }
        }
    }

    public void OnActionExecuted(ActionExecutedContext context) { }

    private static object NormalizeObject(object obj, string path)
    {
        if (obj is string s) return NormalizeString(s, path);

        var t = obj.GetType();
        if (t.IsPrimitive || t.IsEnum) return obj;

        if (obj is System.Collections.IList list)
        {
            for (var i = 0; i < list.Count; i++)
            {
                var item = list[i];
                if (item is null) continue;
                var normalized = NormalizeObject(item, path + "[" + i + "]");
                if (!ReferenceEquals(item, normalized)) list[i] = normalized;
            }
            return obj;
        }

        foreach (var prop in t.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            if (!prop.CanRead) continue;
            var childPath = string.IsNullOrEmpty(path) ? prop.Name : path + "." + prop.Name;
            object? current;
            try { current = prop.GetValue(obj); } catch { continue; }
            if (current is null) continue;

            if (prop.PropertyType == typeof(string))
            {
                if (!prop.CanWrite) continue;
                prop.SetValue(obj, NormalizeString((string)current, childPath));
            }
            else if (!prop.PropertyType.IsPrimitive && !prop.PropertyType.IsEnum && prop.CanWrite)
            {
                var normalized = NormalizeObject(current, childPath);
                if (!ReferenceEquals(current, normalized)) prop.SetValue(obj, normalized);
            }
        }
        return obj;
    }

    private static string NormalizeString(string input, string path)
    {
        var s = input.Normalize(System.Text.NormalizationForm.FormKC).Trim();
        s = CollapseWs.Replace(s, " ");
        foreach (var ch in s)
        {
            if (char.IsControl(ch) && ch != '\r' && ch != '\n' && ch != '\t')
                throw new ValidationException($"Field '{path}' contains control characters.");
        }
        return s;
    }

    private static IDictionary<string, JsonElement>? GetExtensionData(object dto)
    {
        var prop = dto.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .FirstOrDefault(p => string.Equals(p.Name, "ExtensionData", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(p.Name, "AdditionalData", StringComparison.OrdinalIgnoreCase));
        if (prop == null) return null;
        return prop.GetValue(dto) as IDictionary<string, JsonElement>;
    }
}