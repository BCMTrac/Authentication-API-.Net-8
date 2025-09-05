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
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using AuthenticationAPI.Services.Email;

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
    private readonly IKeyRingService _keyRing;
    private readonly ITotpService _totp;
    private readonly IEmailSender _email;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext db,
            IRefreshTokenService refreshTokenService,
            IKeyRingService keyRing,
            ITotpService totp,
            IEmailSender email)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _db = db;
            _refreshTokenService = refreshTokenService;
            _keyRing = keyRing;
            _totp = totp;
            _email = email;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password)) return Unauthorized();
            if (user.MfaEnabled && string.IsNullOrWhiteSpace(model.MfaCode))
            {
                return Ok(new { mfaRequired = true });
            }
            if (user.MfaEnabled)
            {
                if (string.IsNullOrWhiteSpace(user.MfaSecret) || !_totp.ValidateCode(user.MfaSecret, model.MfaCode!, out _))
                {
                    return Unauthorized(new { error = "Invalid MFA code" });
                }
            }

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
            var key = _keyRing.GetActiveSigningKeyAsync().GetAwaiter().GetResult();
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(key.Secret), out _);
            var creds = new SigningCredentials(new RsaSecurityKey(rsa) { KeyId = key.Kid }, SecurityAlgorithms.RsaSha256);
            var tokenLifetimeMinutes = int.TryParse(_configuration["JWT:AccessTokenMinutes"], out var m) ? m : 180;
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: authClaims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(tokenLifetimeMinutes),
                signingCredentials: creds);
            token.Header["kid"] = key.Kid;
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

        [HttpPost("request-password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok(); // do not reveal existence
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _email.SendAsync(user.Email!, "Password reset",
                $"Use this token to reset your password: {token}");
            return Ok();
        }

        [HttpPost("confirm-password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmPasswordReset([FromBody] PasswordResetConfirmDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest();
            var res = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
            if (!res.Succeeded) return BadRequest(new { errors = res.Errors.Select(e => e.Description) });
            return Ok();
        }

        [HttpPost("request-email-confirm")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestEmailConfirm([FromBody] EmailRequestDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok();
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _email.SendAsync(user.Email!, "Email confirmation",
                $"Use this token to confirm your email: {token}");
            return Ok();
        }

        [HttpPost("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest();
            var res = await _userManager.ConfirmEmailAsync(user, dto.Token);
            if (!res.Succeeded) return BadRequest(new { errors = res.Errors.Select(e => e.Description) });
            return Ok();
        }

        [HttpPost("mfa/enroll/start")]
        [Authorize]
        public async Task<IActionResult> MfaEnrollStart()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (user.MfaEnabled) return BadRequest(new { error = "Already enabled" });
            var secret = _totp.GenerateSecret();
            user.MfaSecret = secret;
            await _userManager.UpdateAsync(user);
            var url = _totp.GetOtpAuthUrl(secret, user.Email ?? user.UserName!, "AuthAPI");
            return Ok(new { secret, otpauthUrl = url });
        }

        [HttpPost("mfa/enroll/confirm")]
        [Authorize]
        public async Task<IActionResult> MfaEnrollConfirm([FromBody] MfaCodeDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (string.IsNullOrWhiteSpace(user.MfaSecret)) return BadRequest(new { error = "No secret generated" });
            if (!_totp.ValidateCode(user.MfaSecret, dto.Code, out _)) return BadRequest(new { error = "Invalid code" });
            user.MfaEnabled = true;
            await _userManager.UpdateAsync(user);
            return Ok(new { enabled = true });
        }

        [HttpPost("mfa/disable")]
        [Authorize]
        public async Task<IActionResult> MfaDisable()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            user.MfaEnabled = false;
            user.MfaSecret = null;
            await _userManager.UpdateAsync(user);
            return Ok();
        }
    }
}

public class RefreshRequest
{
    public string RefreshToken { get; set; } = null!;
}

public class PasswordResetRequestDto { public string Email { get; set; } = string.Empty; }
public class PasswordResetConfirmDto { public string Email { get; set; } = string.Empty; public string Token { get; set; } = string.Empty; public string NewPassword { get; set; } = string.Empty; }
public class EmailRequestDto { public string Email { get; set; } = string.Empty; }
public class EmailConfirmDto { public string Email { get; set; } = string.Empty; public string Token { get; set; } = string.Empty; }
public class MfaCodeDto { public string Code { get; set; } = string.Empty; }
// Extend LoginModel to include MFA code (optional)
