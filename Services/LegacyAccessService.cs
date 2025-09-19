using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Data;
using AuthenticationAPI.Infrastructure.Security;
using AuthenticationAPI.Models;
using AuthenticationAPI.Models.Options;
using AuthenticationAPI.Models.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services;

public interface ILegacyAccessService
{
    Task<IReadOnlyCollection<string>> GetRolesForUserAsync(ApplicationUser user);
    Task<IReadOnlyCollection<SchemeItem>> GetSchemesForAsync(ApplicationUser user, string role);
    void EmitLegacyHeaders(HttpResponse response, BridgeOptions bridge, Guid sessionId);
    Task<string> IssueUiJwtAsync(ApplicationUser user, string selectedRole, string selectedScheme, IServiceProvider sp);
    Task<string> GetAccessRightsCookieValueAsync(ApplicationUser user, string selectedRole, string selectedScheme);
    Task<string?> GetSiteAdminCookieAsync(ApplicationUser user);
}

public class LegacyAccessService : ILegacyAccessService
{
    private readonly LegacyDbOptions _opts;
    private readonly IConfiguration _config;

    public LegacyAccessService(IOptions<LegacyDbOptions> opts, IConfiguration config)
    {
        _opts = opts.Value; _config = config;
    }
    public class AccessRights
    {
        public bool AdminDashboard { get; set; }
        public bool AdminManageUsers { get; set; }
        public bool AdminManageSchemes { get; set; }
        public bool ManageCompanies { get; set; }
        public bool ManageBudgets { get; set; }
        // Add more flags as needed from legacy
    }

    public async Task<IReadOnlyCollection<string>> GetRolesForUserAsync(ApplicationUser user)
    {
        var connStr = ResolveConn();
        if (connStr == null)
            return new[] { "User" } as IReadOnlyCollection<string>;

        using var conn = new SqlConnection(connStr);
        await conn.OpenAsync();
        var uid = await ResolveLegacyUserIdAsync(conn, user);
        if (!string.IsNullOrWhiteSpace(_opts.RolesTable) &&
            !string.IsNullOrWhiteSpace(_opts.RoleUserIdColumn) &&
            !string.IsNullOrWhiteSpace(_opts.RoleNameColumn))
        {
            var sql = $"SELECT DISTINCT [{_opts.RoleNameColumn}] FROM [{_opts.RolesTable}] WHERE [{_opts.RoleUserIdColumn}] = @uid";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.Add(new SqlParameter("@uid", uid));
            var list = new List<string>();
            using var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess);
            while (await reader.ReadAsync())
            {
                if (!reader.IsDBNull(0)) list.Add(reader.GetString(0));
            }
            if (list.Count > 0) return list;
        }
        // Fallback: derive roles from SchemeCookie.SchemeType for this user
        if (!string.IsNullOrWhiteSpace(_opts.SchemesTable) &&
            !string.IsNullOrWhiteSpace(_opts.SchemeUserIdColumn) &&
            !string.IsNullOrWhiteSpace(_opts.SchemeTypeColumn))
        {
            var sql = $"SELECT DISTINCT [{_opts.SchemeTypeColumn}] FROM [{_opts.SchemesTable}] WHERE [{_opts.SchemeUserIdColumn}] = @uid";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.Add(new SqlParameter("@uid", uid));
            var list = new List<string>();
            using var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess);
            while (await reader.ReadAsync())
            {
                if (!reader.IsDBNull(0)) list.Add(reader.GetString(0));
            }
            if (list.Count > 0) return list;
        }
        return new[] { "User" };
    }

    public async Task<IReadOnlyCollection<SchemeItem>> GetSchemesForAsync(ApplicationUser user, string role)
    {
        var connStr = ResolveConn();
        if (connStr == null || string.IsNullOrWhiteSpace(_opts.SchemesTable))
            return new[] { new SchemeItem("1","Example Scheme A","Company", "General") } as IReadOnlyCollection<SchemeItem>;

        using var conn = new SqlConnection(connStr);
        await conn.OpenAsync();
        var uid = await ResolveLegacyUserIdAsync(conn, user);
        var categoryCol = !string.IsNullOrWhiteSpace(_opts.SchemeCategoryColumn) ? _opts.SchemeCategoryColumn : _opts.SchemeTypeColumn;
        var sql = $@"SELECT DISTINCT 
                CAST([{_opts.SchemeIdColumn}] AS nvarchar(100)) AS Id,
                CAST([{_opts.SchemeNameColumn}] AS nvarchar(200)) AS Name,
                CAST([{_opts.SchemeTypeColumn}] AS nvarchar(100)) AS Type,
                CAST([{categoryCol}] AS nvarchar(100)) AS Category
            FROM [{_opts.SchemesTable}]
            WHERE [{_opts.SchemeUserIdColumn}] = @uid AND [{_opts.SchemeRoleColumn}] = @role";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@uid", uid));
        cmd.Parameters.Add(new SqlParameter("@role", role));
        var list = new List<SchemeItem>();
        using var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess);
        var idOrd = reader.GetOrdinal("Id");
        var nameOrd = reader.GetOrdinal("Name");
        var typeOrd = reader.GetOrdinal("Type");
        var catOrd = reader.GetOrdinal("Category");
        while (await reader.ReadAsync())
        {
            var id = reader.IsDBNull(idOrd) ? string.Empty : reader.GetString(idOrd);
            var name = reader.IsDBNull(nameOrd) ? string.Empty : reader.GetString(nameOrd);
            var type = reader.IsDBNull(typeOrd) ? string.Empty : reader.GetString(typeOrd);
            var category = reader.IsDBNull(catOrd) ? string.Empty : reader.GetString(catOrd);
            list.Add(new SchemeItem(id, name, type, category));
        }
        return list;
    }

    public void EmitLegacyHeaders(HttpResponse response, BridgeOptions bridge, Guid sessionId)
    {
        if (!bridge.Enabled) return;
        foreach (var name in bridge.HeaderNames)
        {
            response.Headers[name] = sessionId.ToString();
        }
    }

    public async Task<string> IssueUiJwtAsync(ApplicationUser user, string selectedRole, string selectedScheme, IServiceProvider sp)
    {
        var keyRing = sp.GetRequiredService<IKeyRingService>();
        var config = sp.GetRequiredService<IConfiguration>();

        var key = await keyRing.GetActiveSigningKeyAsync();
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(key.Secret), out _);
        var creds = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = key.Kid }, SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? user.Email ?? user.Id),
            new Claim(AuthConstants.ClaimTypes.SelectedRole, selectedRole),
            new Claim(AuthConstants.ClaimTypes.SelectedScheme, selectedScheme)
        };

        var tokenLifetimeMinutes = int.TryParse(config["JWT:AccessTokenMinutes"], out var m) ? m : 180;
        var token = new JwtSecurityToken(
            issuer: config["JWT:ValidIssuer"],
            audience: config["JWT:ValidAudience"],
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(tokenLifetimeMinutes),
            signingCredentials: creds);
        token.Header["kid"] = key.Kid;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<string> GetAccessRightsCookieValueAsync(ApplicationUser user, string selectedRole, string selectedScheme)
    {
        var connStr = ResolveConn();
        if (connStr == null || string.IsNullOrWhiteSpace(_opts.AccessRightsTable))
        {
            // Fallback minimal rights if not configured
            return "ManageCompanies=1;AdminDashboard=0";
        }
        using var conn = new SqlConnection(connStr);
        await conn.OpenAsync();
        var uid = await ResolveLegacyUserIdAsync(conn, user);
        var where = _opts.AccessRightsSchemeIdColumn is { Length: > 0 }
            ? $"WHERE [{_opts.AccessRightsUserIdColumn}] = @uid AND [{_opts.AccessRightsSchemeIdColumn}] = @scheme"
            : $"WHERE [{_opts.AccessRightsUserIdColumn}] = @uid";
        var sql = $"SELECT TOP 1 * FROM [{_opts.AccessRightsTable}] {where}";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@uid", uid));
        if (_opts.AccessRightsSchemeIdColumn is { Length: > 0 })
            cmd.Parameters.Add(new SqlParameter("@scheme", selectedScheme));
        using var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SingleRow);
        if (!await reader.ReadAsync()) return "AdminDashboard=0";
        var parts = new List<string>();
        for (int i = 0; i < reader.FieldCount; i++)
        {
            var name = reader.GetName(i);
            if (reader.IsDBNull(i)) continue;
            var val = reader.GetValue(i);
            var flag = ToBooleanLike(val);
            if (flag.HasValue)
            {
                parts.Add($"{name}={(flag.Value ? 1 : 0)}");
            }
        }
        return string.Join(";", parts);
    }

    public async Task<string?> GetSiteAdminCookieAsync(ApplicationUser user)
    {
        var connStr = ResolveConn();
        if (connStr == null) return null;
        using var conn = new SqlConnection(connStr);
        await conn.OpenAsync();
        var uid = await ResolveLegacyUserIdAsync(conn, user);
        var sql = "SELECT TOP 1 [AdminbackOfficeCookieID] FROM [SiteAdminUsers] WHERE [usID] = @uid ORDER BY [ID] DESC";
        using var cmd = new SqlCommand(sql, conn);
        cmd.Parameters.Add(new SqlParameter("@uid", uid));
        var obj = await cmd.ExecuteScalarAsync();
        var cookie = obj?.ToString();
        return string.IsNullOrWhiteSpace(cookie) ? null : cookie;
    }

    private string? ResolveConn()
    {
        if (!string.IsNullOrWhiteSpace(_opts.ConnectionString)) return _opts.ConnectionString;
        var name = _config.GetConnectionString("LegacyDb");
        return string.IsNullOrWhiteSpace(name) ? null : name;
    }

    private async Task<string> ResolveLegacyUserIdAsync(SqlConnection conn, ApplicationUser user)
    {
        // Try to find legacy user id by email, then username
        if (!string.IsNullOrWhiteSpace(_opts.UserTable))
        {
            if (!string.IsNullOrWhiteSpace(user.Email) && !string.IsNullOrWhiteSpace(_opts.EmailColumn))
            {
                var sqlByEmail = $"SELECT TOP 1 [{_opts.UserIdColumn}] FROM [{_opts.UserTable}] WHERE [{_opts.EmailColumn}] = @email";
                using (var cmd = new SqlCommand(sqlByEmail, conn))
                {
                    cmd.Parameters.Add(new SqlParameter("@email", user.Email));
                    var byEmailObj = await cmd.ExecuteScalarAsync();
                    var byEmail = byEmailObj?.ToString();
                    if (!string.IsNullOrWhiteSpace(byEmail)) return byEmail;
                }
            }
            if (!string.IsNullOrWhiteSpace(_opts.UsernameColumn))
            {
                var sqlByUser = $"SELECT TOP 1 [{_opts.UserIdColumn}] FROM [{_opts.UserTable}] WHERE [{_opts.UsernameColumn}] = @username";
                using (var cmd = new SqlCommand(sqlByUser, conn))
                {
                    cmd.Parameters.Add(new SqlParameter("@username", user.UserName ?? string.Empty));
                    var byUserObj = await cmd.ExecuteScalarAsync();
                    var byUser = byUserObj?.ToString();
                    if (!string.IsNullOrWhiteSpace(byUser)) return byUser;
                }
            }
        }
        // Fallback: use ASP.NET user id
        return user.Id;
    }

    private static bool? ToBooleanLike(object value)
    {
        switch (value)
        {
            case bool b:
                return b;
            case byte by:
                return by != 0;
            case short s:
                return s != 0;
            case int i:
                return i != 0;
            case long l:
                return l != 0;
            case string str:
                if (bool.TryParse(str, out var bb)) return bb;
                if (int.TryParse(str, out var ii)) return ii != 0;
                return null;
            default:
                return null;
        }
    }
}
