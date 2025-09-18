namespace AuthenticationAPI.Models.Options;

public sealed class LegacyDbOptions
{
    public const string SectionName = "LegacyDb";
    // Connection string or name; if a name, it will be looked up under ConnectionStrings
    public string? ConnectionString { get; set; }

    // Users mapping
    public string? UserTable { get; set; }
    public string? UserIdColumn { get; set; }
    public string? EmailColumn { get; set; }
    public string? UsernameColumn { get; set; }

    // Roles mapping
    public string? RolesTable { get; set; }
    public string? RoleUserIdColumn { get; set; }
    public string? RoleNameColumn { get; set; }

    // Schemes mapping
    public string? SchemesTable { get; set; }
    public string? SchemeUserIdColumn { get; set; }
    public string? SchemeRoleColumn { get; set; }
    public string? SchemeIdColumn { get; set; }
    public string? SchemeNameColumn { get; set; }
    public string? SchemeTypeColumn { get; set; }

    // Access rights mapping
    public string? AccessRightsTable { get; set; }
    public string? AccessRightsUserIdColumn { get; set; }
    public string? AccessRightsSchemeIdColumn { get; set; } // optional; if null, rights are per-user
}
