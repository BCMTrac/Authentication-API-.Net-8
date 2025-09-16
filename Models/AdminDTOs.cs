namespace AuthenticationAPI.Models;

// DTOs for AdminController responses

public record UserSummaryDto(string Id, string? UserName, string? Email, bool EmailConfirmed, System.DateTimeOffset? LockoutEnd, bool MfaEnabled);

public record UserDetailDto(string Id, string? UserName, string? Email, bool EmailConfirmed, string? PhoneNumber, string? FullName, System.DateTimeOffset? LockoutEnd, bool MfaEnabled, System.Collections.Generic.IList<string> Roles);

public record RoleDto(string Role);

public record SessionDto(System.Guid Id, System.DateTime CreatedUtc, System.DateTime? LastSeenUtc, System.DateTime? RevokedAtUtc, string? Ip, string? UserAgent);

public record TempPasswordDto(string NewPassword);

public record TestEmailDto(string To, string? Subject, string? Body);
