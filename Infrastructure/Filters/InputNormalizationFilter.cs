using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthenticationAPI.Infrastructure.Filters;

/// <summary>
/// Normalizes all incoming string fields (trim + collapse internal whitespace + Unicode NFKC),
/// enforces payload size limits, rejects control characters, and enforces additionalProperties=false
/// by detecting unknown JSON fields via JsonExtensionData in DTO base type.
/// </summary>
public sealed class InputNormalizationFilter : IActionFilter
{
    // 20 KB default max payload size
    private const long MaxBodyBytes = 20 * 1024;

    private static readonly Regex CollapseWs = new Regex("\\s+", RegexOptions.Compiled);

    public void OnActionExecuting(ActionExecutingContext context)
    {
        // Guard request size via Content-Length when present; if not present, stream length may be unknown.
        if (context.HttpContext.Request.ContentLength.HasValue)
        {
            if (context.HttpContext.Request.ContentLength.Value > MaxBodyBytes)
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
                list.Add(NormalizeObject(item, propertyPath + $"[{idx}]") );
                idx++;
            }
            return list;
        }

        // Normalize all writable string properties on complex objects
        foreach (var prop in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!prop.CanRead || !prop.CanWrite) continue;
            // Skip indexers (e.g., Dictionary<TKey,TValue>.Item) to avoid reflection SetValue parameter mismatch
            if (prop.GetIndexParameters().Length > 0) continue;
            var val = prop.GetValue(obj);
            if (val is null) continue;
            if (val is string sv)
            {
                var normalized = NormalizeString(sv, propertyPath + "." + prop.Name);
                prop.SetValue(obj, normalized);
            }
            else if (!prop.PropertyType.IsPrimitive && !prop.PropertyType.IsEnum)
            {
                // Avoid diving into dictionaries and general enumerables (other than strings)
                var isString = val is string;
                var isDictionary = typeof(System.Collections.IDictionary).IsAssignableFrom(prop.PropertyType);
                var isEnumerable = !isString && typeof(System.Collections.IEnumerable).IsAssignableFrom(prop.PropertyType);
                if (isDictionary || isEnumerable)
                {
                    // Skip normalization for nested collections/dictionaries to prevent reflection errors
                    continue;
                }
                var newVal = NormalizeObject(val, propertyPath + "." + prop.Name);
                prop.SetValue(obj, newVal);
            }
        }

        return obj;
    }

    private static string NormalizeString(string input, string path)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;

        // Unicode normalize to NFKC
        var s = input.Normalize(NormalizationForm.FormKC);

        // Trim
        s = s.Trim();

        // Reject control characters (C0), allow CR/LF/TAB only for fields unlikely here; default to rejecting all
        foreach (var ch in s)
        {
            if (char.IsControl(ch))
            {
                // Reject all control chars; specific free-text fields can be exempted later if needed
                throw new ValidationException($"Invalid control character in field '{path}'.");
            }
        }

        var lastSegment = path.Split('.').Last();

        // Collapse internal whitespace for typical text fields
        var isToken = path.EndsWith("Token", StringComparison.OrdinalIgnoreCase) ||
                      path.Contains("Token.", StringComparison.OrdinalIgnoreCase) ||
                      path.EndsWith("Code", StringComparison.OrdinalIgnoreCase) ||
                      path.EndsWith("RefreshToken", StringComparison.OrdinalIgnoreCase);

        if (!isToken)
        {
            s = CollapseWs.Replace(s, " ");
        }
        else
        {
            // For token-like fields, reject internal whitespace rather than collapsing
            if (s.Any(char.IsWhiteSpace))
            {
                throw new ValidationException($"Whitespace is not allowed in field '{path}'.");
            }
        }

        // Lowercase emails by common property name convention
        if (string.Equals(lastSegment, "Email", StringComparison.OrdinalIgnoreCase))
        {
            s = s.ToLowerInvariant();
        }

        // Reject angle brackets anywhere to prevent accidental HTML/script injection in common fields
        if (s.Contains('<') || s.Contains('>'))
        {
            throw new ValidationException($"Invalid characters in field '{path}'.");
        }

        // For full names, strip leading/trailing punctuation
        if (string.Equals(lastSegment, "FullName", StringComparison.OrdinalIgnoreCase))
        {
            int start = 0, end = s.Length - 1;
            while (start <= end && char.IsPunctuation(s[start])) start++;
            while (end >= start && char.IsPunctuation(s[end])) end--;
            s = start <= end ? s.Substring(start, end - start + 1) : string.Empty;
        }

        return s;
    }

    private static IReadOnlyDictionary<string, JsonElement>? GetExtensionData(object obj)
    {
        // If DTO inherits StrictDtoBase, retrieve extension data for unexpected fields check
        var t = obj.GetType();
        var prop = t.GetProperty("ExtensionData", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        if (prop == null) return null;
        var val = prop.GetValue(obj);
        if (val is null) return null;
        if (val is IReadOnlyDictionary<string, JsonElement> ro) return ro;
        if (val is IDictionary<string, JsonElement> dict) return new Dictionary<string, JsonElement>(dict);
        if (val is Dictionary<string, JsonElement> d) return d;
        return null;
    }
}
