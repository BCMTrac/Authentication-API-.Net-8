using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Services
{
    public class AuditService : IAuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditService(ApplicationDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogAsync(string action, string? targetEntityType = null, string? targetEntityId = null, object? details = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return; // Cannot audit outside of a request context

            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userName = httpContext.User.Identity?.Name;

            var auditLog = new AuditLog
            {
                UserId = userId,
                UserName = userName,
                Action = action,
                TargetEntityType = targetEntityType,
                TargetEntityId = targetEntityId,
                Details = details != null ? JsonSerializer.Serialize(details) : null,
                // The following fields will be populated by the existing middleware
                Method = httpContext.Request.Method,
                Path = httpContext.Request.Path,
                ClientIp = httpContext.Connection.RemoteIpAddress?.ToString(),
                CorrelationId = httpContext.TraceIdentifier,
                StatusCode = httpContext.Response.StatusCode, // This will be the status code before this specific action
                DurationMs = 0 // Duration is calculated by middleware, not relevant here
            };

            await _context.AuditLogs.AddAsync(auditLog);
            // Note: SaveChanges will be called by the middleware at the end of the request.
            // Or, if you want to ensure it's saved immediately, you can call it here.
            // For now, we rely on the middleware's SaveChanges.
        }
    }
}
