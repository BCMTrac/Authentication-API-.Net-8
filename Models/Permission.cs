using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthenticationAPI.Models;

public class Permission
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(100)]
    public string Name { get; set; } = null!; // e.g. users.read

    [MaxLength(300)]
    public string? Description { get; set; }

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class RolePermission
{
    [Required]
    public string RoleId { get; set; } = null!;
    [ForeignKey(nameof(RoleId))]
    public Microsoft.AspNetCore.Identity.IdentityRole? Role { get; set; }

    [Required]
    public Guid PermissionId { get; set; }
    public Permission? Permission { get; set; }
}

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = null!;
    public ApplicationUser? User { get; set; }
    public string TokenHash { get; set; } = null!; // SHA256 of token
    public DateTime ExpiresUtc { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public string CreatedIp { get; set; } = "unknown";
    public Guid? SessionId { get; set; }
    public Session? Session { get; set; }
    public DateTime? RevokedUtc { get; set; }
    public string? RevokedReason { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    [Timestamp]
    public byte[]? RowVersion { get; set; } // Optimistic concurrency
    public bool IsActive => RevokedUtc == null && DateTime.UtcNow < ExpiresUtc;
}

public class AuditLog
{
    [Key]
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public string Method { get; set; } = null!;
    public string Path { get; set; } = null!;
    public int StatusCode { get; set; }
    public long DurationMs { get; set; }
    public string? CorrelationId { get; set; }
    public string? ClientIp { get; set; }
}

public class IdempotencyRecord
{
    [Key]
    public string Key { get; set; } = null!; // Provided by client
    public string RequestHash { get; set; } = null!; // Hash of method+path+body
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public int StatusCode { get; set; }
    public string ResponseBody { get; set; } = null!;
    public string ContentType { get; set; } = "application/json";
    public DateTime? ExpiresUtc { get; set; } // optional expiration
}

public class Session
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required]
    public string UserId { get; set; } = null!;
    public ApplicationUser? User { get; set; }
    [MaxLength(64)]
    public string? DeviceId { get; set; }
    [MaxLength(64)]
    public string? Ip { get; set; }
    [MaxLength(256)]
    public string? UserAgent { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastSeenUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}
