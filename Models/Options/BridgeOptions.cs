namespace AuthenticationAPI.Models.Options;

public sealed class BridgeOptions
{
    public const string SectionName = "Bridge";
    public bool Enabled { get; set; } = false;
    // API key header name and value used by legacy systems or YARP to call back
    public string ApiKeyHeader { get; set; } = "X-Bridge-Api-Key";
    public string? ApiKey { get; set; } = null;
    // Names of headers to emit that YARP will map to legacy cookies
    public string[] HeaderNames { get; set; } = new[]
    {
        "X-Legacy-Session-1",
        "X-Legacy-Session-2",
        "X-Legacy-Session-3"
    };
    // Explicit legacy cookie names used by the monolith
    public string AdminBackOfficeCookieName { get; set; } = "AdminBackOffcieCookie"; // note: legacy spelling
    public string SchemeCookieName { get; set; } = "SchemeCookie";
    public string AccessRightsCookieName { get; set; } = "UserAccessRights";
    public string SiteAdminCookieName { get; set; } = "SiteAdminCookie";
    public string SiteAdminCookieKey { get; set; } = "SiteAdminCookieID";
    // Optional header name to carry the JWT if YARP needs to set a cookie for it
    public string JwtHeaderName { get; set; } = "X-Auth-JWT";
    // Optional cookie name to carry the JWT if legacy app expects a cookie
    public string? JwtCookieName { get; set; } = null;
}

