using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
using Microsoft.AspNetCore.RateLimiting;
using QRCoder; // add QR code generator types

namespace AuthenticationAPI.Controllers
{
    [Route("api/v1/authenticate")]
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
    private readonly IMfaSecretProtector _protector;
    private readonly IRecoveryCodeService _recoveryCodes;
    private readonly ISessionService _sessions;
    private readonly IHostEnvironment _env;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext db,
            IRefreshTokenService refreshTokenService,
            IKeyRingService keyRing,
            ITotpService totp,
            IEmailSender email,
            IMfaSecretProtector protector,
            IRecoveryCodeService recoveryCodes,
            ISessionService sessions,
            IHostEnvironment env)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _db = db;
            _refreshTokenService = refreshTokenService;
            _keyRing = keyRing;
            _totp = totp;
            _email = email;
            _protector = protector;
            _recoveryCodes = recoveryCodes;
            _sessions = sessions;
            _env = env;
        }

        [HttpPost]
        [Route("login")]
        [EnableRateLimiting("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password)) return Unauthorized();
            if (!user.EmailConfirmed)
            {
                return Unauthorized(new { error = "Email not confirmed" });
            }
            if (user.MfaEnabled && string.IsNullOrWhiteSpace(model.MfaCode))
            {
                return Ok(new { mfaRequired = true });
            }
            if (user.MfaEnabled)
            {
                if (string.IsNullOrWhiteSpace(user.MfaSecret)) return Unauthorized(new { error = "MFA not initialized" });
                var secret = _protector.Unprotect(user.MfaSecret);
                if (string.IsNullOrWhiteSpace(secret)) return Unauthorized(new { error = "MFA secret unavailable" });
                if (!_totp.ValidateCode(secret, model.MfaCode!, out var ts))
                {
                    // Check recovery codes fallback
                    var used = await _recoveryCodes.RedeemAsync(user, model.MfaCode!, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                    if (!used) return Unauthorized(new { error = "Invalid MFA code" });
                }
                else
                {
                    // anti-replay: ensure not previously accepted
                    if (ts <= user.MfaLastTimeStep)
                        return Unauthorized(new { error = "Stale MFA code" });
                    user.MfaLastTimeStep = ts;
                    await _userManager.UpdateAsync(user);
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
            // Create session and issue tokens
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = Request.Headers["User-Agent"].ToString();
            var session = await _sessions.CreateAsync(user, ip, ua);
            authClaims.Add(new Claim("sid", session.Id.ToString()));
            var token = GetToken(authClaims);
            var (refreshToken, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, session.Id);

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
        [EnableRateLimiting("register")]
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
        [EnableRateLimiting("register")]
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
            if (stored == null)
            {
                // Detect refresh token reuse attempts and globally revoke if detected
                await _refreshTokenService.HandleReuseAttemptAsync(request.RefreshToken);
                return Unauthorized();
            }
            if (stored.SessionId.HasValue)
            {
                await _sessions.TouchAsync(stored.SessionId.Value);
            }
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
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var (newRefresh, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, stored.SessionId ?? Guid.Empty);
            await _refreshTokenService.RevokeAndLinkAsync(request.RefreshToken, newRefresh, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                refreshToken = newRefresh,
                refreshTokenExpiration = refreshExp
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            // Revoke the session associated with the provided refresh token
            var stored = await _refreshTokenService.ValidateAsync(request.RefreshToken);
            if (stored == null)
            {
                await _refreshTokenService.HandleReuseAttemptAsync(request.RefreshToken);
                return Ok(); // idempotent
            }
            if (stored.SessionId.HasValue)
            {
                await _sessions.RevokeAsync(stored.SessionId.Value, "logout");
            }
            else
            {
                // No session tracked: best-effort revoke this token only
                await _refreshTokenService.RevokeAsync(request.RefreshToken, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "logout");
            }
            return Ok();
        }

        [HttpPost("logout-all")]
        [Authorize]
        public async Task<IActionResult> LogoutAll()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            await _sessions.RevokeAllForUserAsync(user.Id, "logout-all");
            user.TokenVersion += 1; // invalidate access tokens too
            await _userManager.UpdateAsync(user);
            return Ok();
        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
            if (!result.Succeeded) return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "password-changed");
            return Ok();
        }

        [HttpPost("change-email/start")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailStart([FromBody] ChangeEmailStartDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (string.Equals(user.Email, dto.NewEmail, StringComparison.OrdinalIgnoreCase)) return BadRequest(new { error = "Email is unchanged" });
            var existing = await _userManager.FindByEmailAsync(dto.NewEmail);
            if (existing != null) return BadRequest(new { error = "Email already in use" });
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, dto.NewEmail);
            // Send to the new address to prove control
            await _email.SendAsync(dto.NewEmail, "Confirm your new email", $"Use this token to confirm your new email: {token}");
            return Ok(new { sent = true });
        }

        [HttpPost("change-email/confirm")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailConfirm([FromBody] ChangeEmailConfirmDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            var result = await _userManager.ChangeEmailAsync(user, dto.NewEmail, dto.Token);
            if (!result.Succeeded) return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
            // Optional: also update username if you want email-as-username policy
            // await _userManager.SetUserNameAsync(user, dto.NewEmail);
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "email-changed");
            return Ok();
        }

        [HttpGet("mfa/qr")]
        [Authorize]
        public async Task<IActionResult> GetMfaQr()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (!user.MfaEnabled || string.IsNullOrWhiteSpace(user.MfaSecret))
                return BadRequest(new { error = "MFA not enabled" });
            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret))
                return BadRequest(new { error = "MFA secret unavailable" });
            var issuer = _configuration["Mfa:Issuer"] ?? _configuration["JWT:ValidIssuer"] ?? "AuthAPI";
            var otpauthUrl = _totp.GetOtpAuthUrl(secret, user.Email ?? user.UserName!, issuer);

            // Generate QR code PNG server-side
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(otpauthUrl, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeImage = qrCode.GetGraphic(20);
            return File(qrCodeImage, "image/png");
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
            await _email.SendAsync(user.Email!, "Password reset", $"Use this token to reset your password: {token}");
            return Ok(new { sent = true });
        }

        [HttpPost("confirm-password-reset")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> ConfirmPasswordReset([FromBody] PasswordResetConfirmDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest();
            var res = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
            if (!res.Succeeded) return BadRequest(new { errors = res.Errors.Select(e => e.Description) });
            // Global session revoke on password reset and bump token version
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "password-reset");
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
            return Ok(new { sent = true });
        }

        [HttpPost("confirm-email")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest(new { error = "Invalid email" });
            if (user.EmailConfirmed) return Ok(new { emailConfirmed = true });
            try
            {
                var res = await _userManager.ConfirmEmailAsync(user, dto.Token);
                if (!res.Succeeded)
                {
                    return BadRequest(new
                    {
                        message = "Invalid or expired confirmation token.",
                        errors = res.Errors.Select(e => e.Description)
                    });
                }
                return Ok(new { emailConfirmed = true });
            }
            catch (Exception)
            {
                // Normalize unexpected provider/store errors into a client-safe response
                return BadRequest(new { message = "Email confirmation failed. Please request a new token and try again." });
            }
        }

        [HttpPost("mfa/enroll/start")]
        [Authorize]
        public async Task<IActionResult> MfaEnrollStart()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (user.MfaEnabled) return BadRequest(new { error = "Already enabled" });
            var secret = _totp.GenerateSecret();
            user.MfaSecret = _protector.Protect(secret);
            await _userManager.UpdateAsync(user);
            var issuer = _configuration["Mfa:Issuer"] ?? _configuration["JWT:ValidIssuer"] ?? "AuthAPI";
            var url = _totp.GetOtpAuthUrl(secret, user.Email ?? user.UserName!, issuer);
            return Ok(new { secret, otpauthUrl = url });
        }

        [HttpPost("mfa/enroll/confirm")]
        [Authorize]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> MfaEnrollConfirm([FromBody] MfaCodeDto dto)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (string.IsNullOrWhiteSpace(user.MfaSecret)) return BadRequest(new { error = "No secret generated" });
            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret)) return BadRequest(new { error = "MFA secret unavailable" });
            if (!_totp.ValidateCode(secret, dto.Code, out var ts)) return BadRequest(new { error = "Invalid code" });
            user.MfaEnabled = true;
            user.MfaLastTimeStep = ts;
            await _userManager.UpdateAsync(user);
            var codes = await _recoveryCodes.GenerateAsync(user);
            return Ok(new { enabled = true, recoveryCodes = codes });
        }

        [HttpPost("mfa/disable")]
        [Authorize]
        public async Task<IActionResult> MfaDisable()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            user.MfaEnabled = false;
            user.MfaSecret = null;
            user.MfaLastTimeStep = -1;
            // Optionally clear recovery codes
            var codes = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
            _db.UserRecoveryCodes.RemoveRange(codes);
            await _db.SaveChangesAsync();
            await _userManager.UpdateAsync(user);
            return Ok();
        }

        [HttpPost("mfa/recovery/regenerate")]
        [Authorize]
        public async Task<IActionResult> RegenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            var existing = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
            _db.UserRecoveryCodes.RemoveRange(existing);
            await _db.SaveChangesAsync();
            var codes = await _recoveryCodes.GenerateAsync(user);
            return Ok(new { recoveryCodes = codes });
        }
    }
}
