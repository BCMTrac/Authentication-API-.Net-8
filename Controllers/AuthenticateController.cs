using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationAPI.Models;
using AuthenticationAPI.Data;
using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _db;
    private readonly IRefreshTokenService _refreshTokenService;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext db,
            IRefreshTokenService refreshTokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _db = db;
            _refreshTokenService = refreshTokenService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                // Add permission claims (scopes) aggregated from role permissions
                var roleIds = await _roleManager.Roles
                    .Where(r => userRoles.Contains(r.Name!))
                    .Select(r => r.Id)
                    .ToListAsync();

                var permissions = await _db.RolePermissions
                    .Where(rp => roleIds.Contains(rp.RoleId))
                    .Include(rp => rp.Permission)
                    .Select(rp => rp.Permission!.Name)
                    .Distinct()
                    .ToListAsync();

                foreach (var perm in permissions)
                {
                    authClaims.Add(new Claim("scope", perm));
                }

                authClaims.Add(new Claim("token_version", user.TokenVersion.ToString()));
                var token = GetToken(authClaims);
                var (refreshToken, refreshExp) = await _refreshTokenService.IssueAsync(user, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    refreshToken,
                    refreshTokenExpiration = refreshExp
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(new
                {
                    Status = "Error",
                    Message = "User creation failed",
                    Errors = result.Errors.Select(e => e.Description)
                });

            await _userManager.AddToRoleAsync(user, "User");

            return Ok(new { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(new
                {
                    Status = "Error",
                    Message = "Admin user creation failed",
                    Errors = result.Errors.Select(e => e.Description)
                });

            await _userManager.AddToRoleAsync(user, "Admin");

            return Ok(new { Status = "Success", Message = "Admin user created successfully!" });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var secret = _configuration["JWT:Secret"];
            if (secret == null)
            {
                throw new InvalidOperationException("JWT secret not configured");
            }
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var stored = await _refreshTokenService.ValidateAsync(request.RefreshToken);
            if (stored == null) return Unauthorized();
            var user = stored.User!;
            var userRoles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("token_version", user.TokenVersion.ToString())
            };
            var roleIds = await _roleManager.Roles
                .Where(r => userRoles.Contains(r.Name!))
                .Select(r => r.Id).ToListAsync();
            var permissions = await _db.RolePermissions.Where(rp => roleIds.Contains(rp.RoleId))
                .Include(rp => rp.Permission)
                .Select(rp => rp.Permission!.Name).Distinct().ToListAsync();
            foreach (var p in permissions) claims.Add(new Claim("scope", p));
            var token = GetToken(claims);
            var (newRefresh, refreshExp) = await _refreshTokenService.IssueAsync(user, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            await _refreshTokenService.RevokeAsync(request.RefreshToken, "rotation", "rotated");
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                refreshToken = newRefresh,
                refreshTokenExpiration = refreshExp
            });
        }

        [HttpPost("revoke-refresh")]
        public async Task<IActionResult> RevokeRefresh([FromBody] RefreshRequest request)
        {
            var ok = await _refreshTokenService.RevokeAsync(request.RefreshToken, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "manual");
            return ok ? Ok() : NotFound();
        }
    }
}

public class RefreshRequest
{
    public string RefreshToken { get; set; } = null!;
}
