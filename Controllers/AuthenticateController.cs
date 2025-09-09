using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationAPI.Models;
using AuthenticationAPI.Data;
using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Net;
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
        private readonly AppDbContext _appDb;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IKeyRingService _keyRing;
    private readonly ITotpService _totp;
    private readonly IEmailSender _email;
    private readonly IEmailTemplateRenderer _templates;
    private readonly IMfaSecretProtector _protector;
    private readonly IRecoveryCodeService _recoveryCodes;
    private readonly AuthenticationAPI.Services.Throttle.IThrottleService _throttle;
    private readonly ISessionService _sessions;

        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext db,
            AppDbContext appDb,
            IRefreshTokenService refreshTokenService,
            IKeyRingService keyRing,
            ITotpService totp,
            IEmailSender email,
            IEmailTemplateRenderer templates,
            IMfaSecretProtector protector,
            IRecoveryCodeService recoveryCodes,
            AuthenticationAPI.Services.Throttle.IThrottleService throttle,
            ISessionService sessions)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _db = db;
            _appDb = appDb;
            _refreshTokenService = refreshTokenService;
            _keyRing = keyRing;
            _totp = totp;
            _email = email;
            _templates = templates;
            _protector = protector;
            _recoveryCodes = recoveryCodes;
            _throttle = throttle;
            _sessions = sessions;
        }

        private static string NormalizeToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return token;
            try
            {
                var decoded = WebUtility.UrlDecode(token);
                return (decoded ?? token).Replace(' ', '+');
            }
            catch
            {
                return token;
            }
        }

        // Cookies removed: refresh tokens are passed only in request bodies now.

        [HttpPost]
        [Route("login")]
        [EnableRateLimiting("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            if (string.IsNullOrEmpty(model.Identifier) || string.IsNullOrEmpty(model.Password) || model.Password.Length > 256)
            {
                return Unauthorized(); // DoS guard / generic response
            }
            var looksLikeEmail = model.Identifier!.Contains('@');
            ApplicationUser? user = looksLikeEmail
                ? await _userManager.FindByEmailAsync(model.Identifier!)
                : await _userManager.FindByNameAsync(model.Identifier!);
            if (user == null)
            {
                // Generic auth failure
                return Unauthorized();
            }
            // Enforce admin/user lockouts
            if (await _userManager.IsLockedOutAsync(user))
            {
                return Unauthorized(new { error = "Account is locked" });
            }
            // Verify password and track failures for lockout policy
            var validPassword = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!validPassword)
            {
                await _userManager.AccessFailedAsync(user);
                return Unauthorized();
            }
            await _userManager.ResetAccessFailedCountAsync(user);
            if (!user.EmailConfirmed)
            {
                return Unauthorized(new { error = "Email not confirmed" });
            }
            if (user.MfaEnabled && string.IsNullOrWhiteSpace(model.MfaCode))
            {
                return Ok(new { mfaRequired = true });
            }
            bool mfaSucceeded = false;
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
                    mfaSucceeded = true;
                }
                else
                {
                    // anti-replay: ensure not previously accepted
                    if (ts <= user.MfaLastTimeStep)
                        return Unauthorized(new { error = "Stale MFA code" });
                    user.MfaLastTimeStep = ts;
                    await _userManager.UpdateAsync(user);
                    mfaSucceeded = true;
                }
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
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

            var permissions = await _appDb.RolePermissions
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
            if (mfaSucceeded)
            {
                authClaims.Add(new Claim("amr", "mfa"));
                var epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                authClaims.Add(new Claim("auth_time", epoch));
            }
            // Create session and issue tokens
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = Request.Headers["User-Agent"].ToString();
            var session = await _sessions.CreateAsync(user, ip, ua);
            authClaims.Add(new Claim("sid", session.Id.ToString()));
            var token = GetToken(authClaims);
            var (refreshToken, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, session.Id);
            // Return refresh token only in response body (no cookies)

            return Ok(new TokenSetResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo,
                RefreshToken = refreshToken,
                RefreshTokenExpiration = refreshExp
            });
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            // Require explicit consent
            if (!model.TermsAccepted)
            {
                return BadRequest(new ApiMessage { Message = "You must accept the terms and conditions." });
            }
            // Deny passwords that contain the username or email local part
            var emailLocal = (model.Email?.Split('@').FirstOrDefault() ?? string.Empty);
            if (!string.IsNullOrEmpty(model.Password))
            {
                var pwLower = model.Password.ToLowerInvariant();
                if ((!string.IsNullOrWhiteSpace(emailLocal) && pwLower.Contains(emailLocal.ToLowerInvariant())) ||
                    (!string.IsNullOrWhiteSpace(model.Username) && pwLower.Contains(model.Username.ToLowerInvariant())))
                {
                    return BadRequest(new ApiMessage { Message = "Password is too similar to account identifiers." });
                }
                // Basic weak pattern checks
                var badFragments = new[] { "password", "qwerty", "123456", "letmein", "welcome" };
                foreach (var frag in badFragments)
                {
                    if (pwLower.Contains(frag)) return BadRequest(new ApiMessage { Message = "Password contains common patterns; choose a stronger one." });
                }
            }

            // Reserved usernames
            var reserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "admin","root","support","system","security","help","contact","postmaster","administrator"
            };
            if (reserved.Contains(model.Username))
            {
                return BadRequest(new ApiMessage { Message = "Username is reserved. Choose another." });
            }

            // Block disposable/temporary email domains
            static bool IsDisposableDomain(string? email)
            {
                if (string.IsNullOrWhiteSpace(email)) return false;
                var at = email.LastIndexOf('@');
                if (at < 0) return false;
                var domain = email[(at+1)..];
                var block = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "mailinator.com","10minutemail.com","guerrillamail.com","yopmail.com","tempmail.com","trashmail.com","getnada.com","dispostable.com"
                };
                return block.Contains(domain);
            }
            if (IsDisposableDomain(model.Email))
            {
                return BadRequest(new ApiMessage { Message = "Disposable email domains are not allowed." });
            }

            // Optional compromised password check (no-op default)
            var compromised = await HttpContext.RequestServices.GetRequiredService<IPasswordBreachChecker>().IsCompromisedAsync(model.Password);
            if (compromised)
            {
                return BadRequest(new ApiMessage { Message = "This password appears in known breaches. Choose a different one." });
            }

            // Enforce uniqueness by email and username
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return BadRequest(new ApiMessage { Message = "If that email exists, we've sent a confirmation link." });
            var emailExists = await _userManager.FindByEmailAsync(model.Email!);
            if (emailExists != null)
            {
                // Always generic to prevent email enumeration
                return Ok(new ApiMessage { Message = "If that email exists, we've sent a confirmation link." });
            }

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                FullName = string.IsNullOrWhiteSpace(model.FullName) ? null : model.FullName,
                TermsAcceptedUtc = DateTime.UtcNow,
                MarketingOptInUtc = model.MarketingOptIn ? DateTime.UtcNow : null
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(new ApiMessage { Message = "User creation failed" });

            await _userManager.AddToRoleAsync(user, "User");

            // Record initial password into history
            await _db.Entry(user).ReloadAsync();
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                _db.PasswordHistory.Add(new PasswordHistory { UserId = user.Id, Hash = user.PasswordHash! });
                await _db.SaveChangesAsync();
            }

            // Optionally capture phone for future MFA via SMS (unconfirmed)
            if (!string.IsNullOrWhiteSpace(model.Phone))
            {
                user.PhoneNumber = model.Phone;
                await _userManager.UpdateAsync(user);
            }

            // Send email confirmation token; in Development, surface SMTP errors to help debug
            try
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmUrlBase = _configuration["Email:EmailConfirm:Url"] ?? string.Empty;
                string? link = string.IsNullOrWhiteSpace(confirmUrlBase) ? null : $"{confirmUrlBase}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
                var (html, text) = await _templates.RenderAsync("email-confirm", new Dictionary<string,string>
                {
                    ["Title"] = "Confirm your email",
                    ["Intro"] = "Thanks for signing up. Please confirm your email to activate your account.",
                    ["ActionText"] = "Confirm Email",
                    ["ActionUrl"] = link ?? string.Empty,
                    ["Token"] = link == null ? token : string.Empty
                });
                await _email.SendAsync(user.Email!, "Confirm your email", html);
            }
            catch (Exception ex)
            {
                // In Development or Production, do not fail registration due to email delivery issues.
                // Log and continue to return a generic response.
                Console.WriteLine($"[EMAIL-ERR][register-confirm] to={user.Email} ex={ex.Message}");
            }

            return Ok(new ApiMessage { Message = "If that email exists, we've sent a confirmation link." });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
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
                return BadRequest(new ApiMessage { Message = "Admin user creation failed" });

            await _userManager.AddToRoleAsync(user, "Admin");

            return Ok(new ApiMessage { Message = "Admin user created successfully!" });
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
            var provided = request.RefreshToken;
            if (string.IsNullOrWhiteSpace(provided)) return Unauthorized();
            var stored = await _refreshTokenService.ValidateAsync(provided);
            if (stored == null)
            {
                // Detect refresh token reuse attempts and globally revoke if detected
                await _refreshTokenService.HandleReuseAttemptAsync(provided);
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
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("token_version", user.TokenVersion.ToString())
            };
            var roleIds = await _roleManager.Roles
                .Where(r => userRoles.Contains(r.Name!))
                .Select(r => r.Id).ToListAsync();
            var permissions = await _appDb.RolePermissions.Where(rp => roleIds.Contains(rp.RoleId))
                .Include(rp => rp.Permission)
                .Select(rp => rp.Permission!.Name).Distinct().ToListAsync();
            foreach (var p in permissions) claims.Add(new Claim("scope", p));
            var token = GetToken(claims);
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var (newRefresh, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, stored.SessionId ?? Guid.Empty);
            await _refreshTokenService.RevokeAndLinkAsync(provided!, newRefresh, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return Ok(new TokenSetResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo,
                RefreshToken = newRefresh,
                RefreshTokenExpiration = refreshExp
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            var provided = request.RefreshToken;
            // Revoke the session associated with the provided refresh token
            var stored = string.IsNullOrWhiteSpace(provided) ? null : await _refreshTokenService.ValidateAsync(provided!);
            if (stored == null)
            {
                if (!string.IsNullOrWhiteSpace(provided))
                {
                    await _refreshTokenService.HandleReuseAttemptAsync(provided!);
                }
                return Ok(); // idempotent
            }
            if (stored.SessionId.HasValue)
            {
                await _sessions.RevokeAsync(stored.SessionId.Value, "logout");
            }
            else
            {
                // No session tracked: best-effort revoke this token only
                await _refreshTokenService.RevokeAsync(provided!, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "logout");
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
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            // Prevent reuse of recent passwords and enforce minimum age based on config
            var reuseWindow = int.TryParse(_configuration["PasswordHistory:ReuseWindowCount"], out var rw) ? Math.Max(1, rw) : 5;
            var minAgeHours = int.TryParse(_configuration["PasswordHistory:MinAgeHours"], out var mh) ? Math.Max(1, mh) : 24;
            var totalHistory = await _db.PasswordHistory.CountAsync(ph => ph.UserId == user.Id);
            var recent = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedUtc).Take(reuseWindow).ToListAsync();
            var hasher = HttpContext.RequestServices.GetRequiredService<IPasswordHasher<ApplicationUser>>();
            foreach (var ph in recent)
            {
                var verdict = hasher.VerifyHashedPassword(user, ph.Hash, dto.NewPassword);
                if (verdict == PasswordVerificationResult.Success)
                {
                    return BadRequest(new ApiMessage { Message = "New password must not match your recent passwords." });
                }
                // Allow immediate change for brand new accounts (initial history entry)
                if (totalHistory > 1 && (DateTime.UtcNow - ph.CreatedUtc).TotalHours < minAgeHours)
                {
                    return BadRequest(new ApiMessage { Message = "Password was changed recently. Try again later." });
                }
            }
            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);
            if (!result.Succeeded) return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "password-changed");
            // record history and cap to last 10
            await _db.Entry(user).ReloadAsync(); // ensure PasswordHash updated
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                _db.PasswordHistory.Add(new PasswordHistory { UserId = user.Id, Hash = user.PasswordHash! });
                await _db.SaveChangesAsync();
                var keep = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedUtc).Skip(10).ToListAsync();
                if (keep.Any())
                {
                    _db.PasswordHistory.RemoveRange(keep);
                    await _db.SaveChangesAsync();
                }
            }
            return Ok();
        }

        [HttpPost("change-email/start")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailStart([FromBody] ChangeEmailStartDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            if (string.Equals(user.Email, dto.NewEmail, StringComparison.OrdinalIgnoreCase)) return BadRequest(new { error = "Email is unchanged" });
            var existing = await _userManager.FindByEmailAsync(dto.NewEmail);
            if (existing != null) return BadRequest(new { error = "Email already in use" });
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, dto.NewEmail);
            // Send to the new address to prove control
            try
            {
                var confirmUrlBase = _configuration["Email:EmailConfirm:Url"] ?? string.Empty;
                string? link = string.IsNullOrWhiteSpace(confirmUrlBase) ? null : $"{confirmUrlBase}?email={Uri.EscapeDataString(dto.NewEmail)}&token={Uri.EscapeDataString(token)}";
                var (html, text) = await _templates.RenderAsync("email-change", new Dictionary<string,string>
                {
                    ["Title"] = "Confirm your new email",
                    ["Intro"] = "Confirm this new email address to complete the change.",
                    ["ActionText"] = "Confirm New Email",
                    ["ActionUrl"] = link ?? string.Empty,
                    ["Token"] = link == null ? token : string.Empty
                });
                await _email.SendAsync(dto.NewEmail, "Confirm your new email", html);
            }
            catch (Exception)
            {
                // Do not fail due to email delivery issues. Log removed for production.
            }
            return Ok(new SentResponse { Sent = true });
        }

        [HttpPost("change-email/confirm")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailConfirm([FromBody] ChangeEmailConfirmDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            var normToken = NormalizeToken(dto.Token);
            var result = await _userManager.ChangeEmailAsync(user, dto.NewEmail, normToken);
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
            var provided = request.RefreshToken;
            if (string.IsNullOrWhiteSpace(provided)) { return NotFound(); }
            var ok = await _refreshTokenService.RevokeAsync(provided!, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "manual");
            return ok ? Ok() : NotFound();
        }

        [HttpPost("request-password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto dto)
        {
            // Per-email throttle: 1/min and 5/day
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var resetKey1m = $"pwd-reset:1m:{dto.Email}";
            var resetKey1d = $"pwd-reset:1d:{dto.Email}";
            var allow1m = await _throttle.AllowAsync(resetKey1m, 1, TimeSpan.FromMinutes(1));
            var allow1d = await _throttle.AllowAsync(resetKey1d, 5, TimeSpan.FromDays(1));
            if (!allow1m || !allow1d) return Ok(new SentResponse { Sent = true });
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok(); // do not reveal existence
            if (!user.EmailConfirmed) return Ok(); // send only to confirmed emails
            if (await _userManager.IsLockedOutAsync(user)) return Ok();
            try
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetUrl = _configuration["PasswordReset:Url"];
                string? link = string.IsNullOrWhiteSpace(resetUrl) ? null : $"{resetUrl}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
                var (html, text) = await _templates.RenderAsync("password-reset", new Dictionary<string,string>
                {
                    ["Title"] = "Reset your password",
                    ["Intro"] = "We received a request to reset your password. If you didn't request this, you can ignore this email.",
                    ["ActionText"] = "Reset Password",
                    ["ActionUrl"] = link ?? string.Empty,
                    ["Token"] = link == null ? token : string.Empty
                });
                await _email.SendAsync(user.Email!, "Password reset", html);
            }
            catch (Exception)
            {
                // Swallow; do not log in production.
            }
            return Ok(new SentResponse { Sent = true });
        }

        [HttpPost("confirm-password-reset")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> ConfirmPasswordReset([FromBody] PasswordResetConfirmDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest();
            var normToken = NormalizeToken(dto.Token);
            // Enforce password history reuse rules
            var reuseWindow = int.TryParse(_configuration["PasswordHistory:ReuseWindowCount"], out var rw) ? Math.Max(1, rw) : 5;
            var keepCount = int.TryParse(_configuration["PasswordHistory:KeepCount"], out var kc) ? Math.Max(reuseWindow, kc) : 12;
            var recent = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedUtc).Take(reuseWindow).ToListAsync();
            var hasher = HttpContext.RequestServices.GetRequiredService<IPasswordHasher<ApplicationUser>>();
            foreach (var ph in recent)
            {
                var verdict = hasher.VerifyHashedPassword(user, ph.Hash, dto.NewPassword);
                if (verdict == PasswordVerificationResult.Success)
                {
                    return BadRequest(new ApiMessage { Message = "New password must not match your recent passwords." });
                }
            }
            var res = await _userManager.ResetPasswordAsync(user, normToken, dto.NewPassword);
            if (!res.Succeeded) return BadRequest(new { errors = res.Errors.Select(e => e.Description) });
            // Global session revoke on password reset and bump token version
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "password-reset");
            // record history and cap
            await _db.Entry(user).ReloadAsync();
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                _db.PasswordHistory.Add(new PasswordHistory { UserId = user.Id, Hash = user.PasswordHash! });
                await _db.SaveChangesAsync();
                var keep = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedUtc).Skip(keepCount).ToListAsync();
                if (keep.Any())
                {
                    _db.PasswordHistory.RemoveRange(keep);
                    await _db.SaveChangesAsync();
                }
            }
            return Ok();
        }

        [HttpPost("request-email-confirm")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> RequestEmailConfirm([FromBody] EmailRequestDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            // Per-email throttle: 1/min and 5/day (silent on refusal)
            var emailKey1m = $"email-confirm:1m:{dto.Email}";
            var emailKey1d = $"email-confirm:1d:{dto.Email}";
            var allow1m = await _throttle.AllowAsync(emailKey1m, 1, TimeSpan.FromMinutes(1));
            var allow1d = await _throttle.AllowAsync(emailKey1d, 5, TimeSpan.FromDays(1));
            if (!allow1m || !allow1d) return Ok(new { sent = true });
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok();
            try
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmUrlBase = _configuration["Email:EmailConfirm:Url"] ?? string.Empty;
                string? link = string.IsNullOrWhiteSpace(confirmUrlBase) ? null : $"{confirmUrlBase}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
                var (html, text) = await _templates.RenderAsync("email-confirm", new Dictionary<string,string>
                {
                    ["Title"] = "Confirm your email",
                    ["Intro"] = "Please confirm your email to activate your account.",
                    ["ActionText"] = "Confirm Email",
                    ["ActionUrl"] = link ?? string.Empty,
                    ["Token"] = link == null ? token : string.Empty
                });
                await _email.SendAsync(user.Email!, "Email confirmation", html);
            }
            catch (Exception)
            {
                // Swallow; do not log in production.
            }
            return Ok(new SentResponse { Sent = true });
        }

        [HttpPost("confirm-email")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return BadRequest(new { error = "Invalid email" });
            if (user.EmailConfirmed) return Ok(new { emailConfirmed = true });
            if (string.IsNullOrWhiteSpace(dto.Token) || dto.Token.Length > 2048 || dto.Token.Any(char.IsWhiteSpace))
            {
                return BadRequest(new { message = "Invalid or expired confirmation token." });
            }
            try
            {
                var normToken = NormalizeToken(dto.Token);
                var res = await _userManager.ConfirmEmailAsync(user, normToken);
                if (!res.Succeeded)
                {
                    return BadRequest(new
                    {
                        message = "Invalid or expired confirmation token.",
                        errors = res.Errors.Select(e => e.Description)
                    });
                }
                return Ok(new EmailConfirmedResponse { EmailConfirmed = true });
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
            return Ok(new OtpAuthResponse { Secret = secret, OtpauthUrl = url });
        }

        [HttpPost("mfa/enroll/confirm")]
        [Authorize]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> MfaEnrollConfirm([FromBody] MfaCodeDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
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
            return Ok(new MfaEnabledResponse { Enabled = true, RecoveryCodes = codes });
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
            return Ok(new RecoveryCodesResponse { RecoveryCodes = codes });
        }
    }
}
