using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Infrastructure.Middleware;

public class AuditAndIdempotencyMiddleware
{
    private readonly RequestDelegate _next;
    private const string IdempotencyHeader = "Idempotency-Key";
    public AuditAndIdempotencyMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext context, ApplicationDbContext db, ILogger<AuditAndIdempotencyMiddleware> logger)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var userId = context.User?.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var userName = context.User?.Identity?.Name;

        // Idempotency (POST/PUT/PATCH only)
        string? idempotencyKey = null;
        IdempotencyRecord? existing = null;
        bool methodEligible = HttpMethods.IsPost(context.Request.Method) || HttpMethods.IsPut(context.Request.Method) || HttpMethods.IsPatch(context.Request.Method);
        if (methodEligible && context.Request.Headers.TryGetValue(IdempotencyHeader, out var keyValues))
        {
            idempotencyKey = keyValues.ToString();
            if (string.IsNullOrWhiteSpace(idempotencyKey))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Idempotency-Key header is empty");
                return;
            }
            try
            {
                existing = await db.IdempotencyRecords.FindAsync(idempotencyKey);
            }
            catch (Exception ex)
            {
                // Table may not exist in some dev DBs; log and continue without idempotency replay
                logger.LogWarning(ex, "Idempotency lookup failed; continuing without replay");
            }
        }

        // Buffer response
        var originalBody = context.Response.Body;
        await using var memStream = new MemoryStream();
        context.Response.Body = memStream;

        // Enable buffering to read body for hashing (only for eligible methods)
        string requestCompositeHash = string.Empty;
        if (methodEligible)
        {
            context.Request.EnableBuffering();
            using var sha = SHA256.Create();
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
            var composite = context.Request.Method + "|" + context.Request.Path + "|" + body;
            requestCompositeHash = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(composite)));
        }

        // If we have an existing record and it hasn't expired, verify hash matches then replay
        if (existing != null && (existing.ExpiresUtc == null || existing.ExpiresUtc > DateTime.UtcNow))
        {
            if (existing.RequestHash != requestCompositeHash)
            {
                context.Response.StatusCode = StatusCodes.Status409Conflict;
                await context.Response.WriteAsync("Idempotency key reuse with different request payload");
                return;
            }
            context.Response.StatusCode = existing.StatusCode;
            context.Response.ContentType = existing.ContentType;
            await context.Response.WriteAsync(existing.ResponseBody);
            logger.LogInformation("Idempotent replay for key {Key}", idempotencyKey);
            return;
        }

        string responseBody = string.Empty;
        try
        {
            await _next(context);
        }
        finally
        {
            try
            {
                sw.Stop();
                memStream.Position = 0;
                responseBody = await new StreamReader(memStream).ReadToEndAsync();
                memStream.Position = 0;
                await memStream.CopyToAsync(originalBody);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to copy buffered response body");
            }
            finally
            {
                context.Response.Body = originalBody;
            }
        }

        // Persist idempotency record if needed
        if (idempotencyKey != null)
        {
            try
            {
                db.IdempotencyRecords.Add(new IdempotencyRecord
                {
                    Key = idempotencyKey,
                    RequestHash = requestCompositeHash,
                    StatusCode = context.Response.StatusCode,
                    ResponseBody = responseBody,
                    ContentType = context.Response.ContentType ?? "application/json",
                    ExpiresUtc = DateTime.UtcNow.AddHours(12)
                });
                logger.LogInformation("Stored idempotency record key={Key} status={Status}", idempotencyKey, context.Response.StatusCode);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to queue idempotency persistence");
            }
        }

        // Audit log
        db.AuditLogs.Add(new AuditLog
        {
            Action = context.Request.Method,
            UserId = userId,
            UserName = userName,
            Method = context.Request.Method,
            Path = context.Request.Path,
            StatusCode = context.Response.StatusCode,
            DurationMs = sw.ElapsedMilliseconds,
            ClientIp = context.Connection.RemoteIpAddress?.ToString(),
            CorrelationId = context.TraceIdentifier
        });

        try
        {
            await db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // swallow auditing/idempotency persistence errors to not break primary flow
        }
    }
}

public static class AuditAndIdempotencyExtensions
{
    public static IApplicationBuilder UseAuditAndIdempotency(this IApplicationBuilder app) => app.UseMiddleware<AuditAndIdempotencyMiddleware>();
}
