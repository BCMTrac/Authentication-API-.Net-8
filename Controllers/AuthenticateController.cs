using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationAPI.Models;
using AuthenticationAPI.Data;
using Microsoft.EntityFrameworkCore;
using AuthenticationAPI.Services;
using AuthenticationAPI.Services.Email;
using AuthenticationAPI.Services.Throttle;
using AuthenticationAPI.Models.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

using Microsoft.AspNetCore.RateLimiting;
using QRCoder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using AuthenticationAPI.Infrastructure.Security;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

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
        private readonly IThrottleService _throttle;
        private readonly ISessionService _sessions;
        private readonly BridgeOptions _bridgeOptions;
        private readonly ILogger<AuthenticateController> _logger;
        private readonly IUserAccountService _userAccountService;

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
            IThrottleService throttle,
            ISessionService sessions,
            Microsoft.Extensions.Options.IOptions<BridgeOptions> bridgeOptions,
            ILogger<AuthenticateController> logger,
            IUserAccountService userAccountService)
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
            _bridgeOptions = bridgeOptions.Value;
            _logger = logger;
            _userAccountService = userAccountService;
        }

        private async Task<bool> ValidateMfa(ApplicationUser user, string? mfaCode)
        {
            if (string.IsNullOrWhiteSpace(mfaCode)) throw new InvalidMfaCodeException();
            if (string.IsNullOrWhiteSpace(user.MfaSecret)) throw new MfaNotInitializedException();

            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret)) throw new MfaNotInitializedException();

            if (_totp.ValidateCode(secret, mfaCode, out var ts))
            {
                if (ts <= user.MfaLastTimeStep) throw new StaleMfaCodeException();
                user.MfaLastTimeStep = ts;
                await _userManager.UpdateAsync(user);
                return true;
            }

            return await _recoveryCodes.RedeemAsync(user, mfaCode, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        }

        private async Task<List<Claim>> GetUserClaimsAsync(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(AuthConstants.ClaimTypes.TokenVersion, user.TokenVersion.ToString())
            };
            foreach (var r in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, r));
            }

            foreach (var userRole in userRoles) claims.Add(new Claim(ClaimTypes.Role, userRole));

            var roleIds = await _roleManager.Roles.Where(r => userRoles.Contains(r.Name!)).Select(r => r.Id).ToListAsync();
            var permissions = await _appDb.RolePermissions.Where(rp => roleIds.Contains(rp.RoleId)).Include(rp => rp.Permission).Select(rp => rp.Permission!.Name).Distinct().ToListAsync();
            foreach (var perm in permissions) claims.Add(new Claim("scope", perm));

            return claims;
        }

        private async Task<TokenSetResponse> CreateTokenResponse(ApplicationUser user, bool mfaSucceeded)
        {
            var claims = await GetUserClaimsAsync(user);

            if (mfaSucceeded)
            {
                claims.Add(new Claim(AuthConstants.ClaimTypes.Amr, AuthConstants.AmrValues.Mfa));
                claims.Add(new Claim("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
            }

            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = Request.Headers["User-Agent"].ToString();
            var session = await _sessions.CreateAsync(user, ip, ua);
            claims.Add(new Claim(AuthConstants.ClaimTypes.SessionId, session.Id.ToString()));

            var token = GetToken(claims);
            var (refreshToken, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, session.Id);

            if (string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                var cookieOpts = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None, Expires = refreshExp, Path = "/api/v1/authenticate" };
                Response.Cookies.Append("rt", refreshToken, cookieOpts);
            }

            if (_bridgeOptions.Enabled)
            {
                foreach (var name in _bridgeOptions.HeaderNames) Response.Headers[name] = session.Id.ToString();
                if (!string.IsNullOrWhiteSpace(_bridgeOptions.JwtHeaderName)) Response.Headers[_bridgeOptions.JwtHeaderName] = new JwtSecurityTokenHandler().WriteToken(token);
            }

            return new TokenSetResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo,
                RefreshToken = refreshToken,
                RefreshTokenExpiration = refreshExp
            };
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

        [HttpPost]
        [Route("register")]
        [EnableRateLimiting("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var compromised = await HttpContext.RequestServices.GetRequiredService<IPasswordBreachChecker>().IsCompromisedAsync(model.Password);
            if (compromised) throw new BadRequestException("This password appears in known breaches. Choose a different one.");

            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null) throw new BadRequestException("A user with that username already exists.");
            var emailExists = await _userManager.FindByEmailAsync(model.Email!);
            if (emailExists != null) throw new EmailAlreadyInUseException();

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                FullName = string.IsNullOrWhiteSpace(model.FullName) ? null : model.FullName,
                TermsAcceptedUtc = model.TermsAccepted ? DateTime.UtcNow : null,
                MarketingOptInUtc = model.MarketingOptIn ? DateTime.UtcNow : null
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) throw new UserCreationException(string.Join(", ", result.Errors.Select(e => e.Description)));

            await _userManager.AddToRoleAsync(user, "User");

            await _db.Entry(user).ReloadAsync();
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                _db.PasswordHistory.Add(new PasswordHistory { UserId = user.Id, Hash = user.PasswordHash! });
                await _db.SaveChangesAsync();
            }

            if (!string.IsNullOrWhiteSpace(model.Phone))
            {
                user.PhoneNumber = model.Phone;
                await _userManager.UpdateAsync(user);
            }

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
                _email.QueueSendAsync(user.Email!, "Confirm your email", html);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to queue confirmation email to {Email} during registration.", user.Email);
            }

            return Ok(new ApiMessage { Message = "If that email exists, we've sent a confirmation link." });
        }

        [HttpPost("refresh")]
        [EnableRateLimiting("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var provided = request.RefreshToken;
            if (string.IsNullOrWhiteSpace(provided) && string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                Request.Cookies.TryGetValue("rt", out provided);
            }
            if (string.IsNullOrWhiteSpace(provided)) throw new BadRequestException("Refresh token is missing.");
            var stored = await _refreshTokenService.ValidateAsync(provided);
            if (stored == null)
            {
                await _refreshTokenService.HandleReuseAttemptAsync(provided);
                throw new InvalidTokenException("Refresh token is invalid or expired.");
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
                new Claim(AuthConstants.ClaimTypes.TokenVersion, user.TokenVersion.ToString())
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

            if (string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                var cookieOpts = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = refreshExp,
                    Path = "/api/v1/authenticate"
                };
                Response.Cookies.Append("rt", newRefresh, cookieOpts);
            }

            if (_bridgeOptions.Enabled && stored.SessionId.HasValue)
            {
                foreach (var name in _bridgeOptions.HeaderNames)
                {
                    Response.Headers[name] = stored.SessionId.Value.ToString();
                }
            }
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
            if (string.IsNullOrWhiteSpace(provided) && string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                Request.Cookies.TryGetValue("rt", out provided);
            }
            var stored = string.IsNullOrWhiteSpace(provided) ? null : await _refreshTokenService.ValidateAsync(provided!);
            if (stored == null)
            {
                if (!string.IsNullOrWhiteSpace(provided))
                {
                    await _refreshTokenService.HandleReuseAttemptAsync(provided!);
                }
                return Ok();
            }
            if (stored.SessionId.HasValue)
            {
                await _sessions.RevokeAsync(stored.SessionId.Value, "logout");
            }
            else
            {
                await _refreshTokenService.RevokeAsync(provided!, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "logout");
            }
            if (string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                Response.Cookies.Delete("rt", new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/api/v1/authenticate"
                });
            }
            return Ok();
        }


        [HttpPost("magic/start")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> MagicStart([FromBody] EmailRequestDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var key1m = $"magic:1m:{dto.Email}";
            var key1d = $"magic:1d:{dto.Email}";
            var allow1m = await _throttle.AllowAsync(key1m, 1, TimeSpan.FromMinutes(1));
            var allow1d = await _throttle.AllowAsync(key1d, 5, TimeSpan.FromDays(1));
            if (!allow1m || !allow1d) return Ok(new SentResponse { Sent = true });
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok(new SentResponse { Sent = true });
            try
            {
                var token = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, AuthConstants.TokenProviders.MagicLink);
                var req = HttpContext.Request;
                var baseUrl = _configuration["MagicLink:Url"] ?? $"{req.Scheme}://{req.Host.Value}/";
                var link = $"{baseUrl}?email={Uri.EscapeDataString(user.Email!)}&magicToken={Uri.EscapeDataString(token)}";
                var (html, _) = await _templates.RenderAsync("email-confirm", new Dictionary<string,string>
                {
                    ["Title"] = "Your sign-in link",
                    ["Intro"] = "Click the button below to sign in. This link expires in 30 minutes.",
                    ["ActionText"] = "Sign in",
                    ["ActionUrl"] = link
                });
                _email.QueueSendAsync(user.Email!, "Your sign-in link", html);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to queue magic link email to {Email}", dto.Email);
            }
            return Ok(new SentResponse { Sent = true });
        }

        [HttpPost("magic/verify")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> MagicVerify([FromBody] EmailConfirmDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) throw new UserNotFoundException();
            var ok = await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, AuthConstants.TokenProviders.MagicLink, dto.Token);
            if (!ok) throw new InvalidTokenException("Magic link is invalid or expired.");

            var userRoles = await _userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(AuthConstants.ClaimTypes.TokenVersion, user.TokenVersion.ToString())
            };
            var roleIds = await _roleManager.Roles.Where(r => userRoles.Contains(r.Name!)).Select(r => r.Id).ToListAsync();
            var permissions = await _appDb.RolePermissions.Where(rp => roleIds.Contains(rp.RoleId)).Include(rp => rp.Permission).Select(rp => rp.Permission!.Name).Distinct().ToListAsync();
            foreach (var p in permissions) claims.Add(new Claim("scope", p));
            var token = GetToken(claims);
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = Request.Headers["User-Agent"].ToString();
            var session = await _sessions.CreateAsync(user, ip, ua);
            var (refresh, refreshExp) = await _refreshTokenService.IssueAsync(user, ip, session.Id);
            if (string.Equals(_configuration["RefreshTokens:UseCookie"], "true", StringComparison.OrdinalIgnoreCase))
            {
                var cookieOpts = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None, Expires = refreshExp, Path = "/api/v1/authenticate" };
                Response.Cookies.Append("rt", refresh, cookieOpts);
            }
            return Ok(new TokenSetResponse { Token = new JwtSecurityTokenHandler().WriteToken(token), Expiration = token.ValidTo, RefreshToken = refresh, RefreshTokenExpiration = refreshExp });
        }

        public record InviteRequestDto(string Email, string? FullName, string[]? Roles);
        public record ActivateRequestDto(string Email, string Token, string Password, string? FullName);

        [HttpPost("invite")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Invite([FromBody] InviteRequestDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email)) throw new BadRequestException("Email is required for invitation.");
            var existing = await _userManager.FindByEmailAsync(dto.Email);
            if (existing != null) throw new EmailAlreadyInUseException();
            var user = new ApplicationUser { UserName = dto.Email, Email = dto.Email, EmailConfirmed = false, FullName = dto.FullName };
            var create = await _userManager.CreateAsync(user);
            if (!create.Succeeded) throw new UserCreationException(string.Join(", ", create.Errors.Select(e => e.Description)));
            if (dto.Roles != null)
            {
                foreach (var r in dto.Roles)
                {
                    if (!await _roleManager.RoleExistsAsync(r)) await _roleManager.CreateAsync(new IdentityRole(r));
                    await _userManager.AddToRoleAsync(user, r);
                }
            }
            try
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var req = HttpContext.Request;
                var baseUrl = _configuration["Activation:Url"] ?? $"{req.Scheme}://{req.Host.Value}/activate";
                var link = $"{baseUrl}?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
                var (html, _) = await _templates.RenderAsync("invite", new Dictionary<string,string>
                {
                    ["Title"] = "You're invited to BCMTrac",
                    ["Intro"] = "Click below to activate your account and set a password.",
                    ["ActionText"] = "Activate account",
                    ["ActionUrl"] = link
                });
                _email.QueueSendAsync(user.Email!, "Invitation to BCMTrac", html);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to queue invitation email to {Email}", dto.Email);
            }
            return Ok(new { invited = true });
        }

        [HttpPost("activate")]
        [AllowAnonymous]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> Activate([FromBody] ActivateRequestDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Token) || string.IsNullOrWhiteSpace(dto.Password)) throw new BadRequestException("Missing activation details.");
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) throw new UserNotFoundException("Invalid activation link.");
            var res = await _userManager.ConfirmEmailAsync(user, dto.Token);
            if (!res.Succeeded && !user.EmailConfirmed) throw new InvalidTokenException("Activation failed. The link may be invalid or expired.");
            if (!string.IsNullOrWhiteSpace(dto.FullName)) { user.FullName = dto.FullName; await _userManager.UpdateAsync(user); }
            var hasPass = await _userManager.HasPasswordAsync(user);
            IdentityResult pwdRes;
            if (!hasPass) pwdRes = await _userManager.AddPasswordAsync(user, dto.Password);
            else { var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user); pwdRes = await _userManager.ResetPasswordAsync(user, resetToken, dto.Password); }
            if (!pwdRes.Succeeded) throw new BadRequestException(string.Join(", ", pwdRes.Errors.Select(e => e.Description)));
            return Ok();
        }

        [HttpPost("logout-all")]
        [Authorize]
        public async Task<IActionResult> LogoutAll()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            await _sessions.RevokeAllForUserAsync(user.Id, "logout-all");
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            return Ok();
        }

        [HttpPost("change-email/start")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailStart([FromBody] ChangeEmailStartDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            if (string.Equals(user.Email, dto.NewEmail, StringComparison.OrdinalIgnoreCase)) throw new BadRequestException("Email is unchanged.");
            var existing = await _userManager.FindByEmailAsync(dto.NewEmail);
            if (existing != null) throw new EmailAlreadyInUseException();
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, dto.NewEmail);
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
                _email.QueueSendAsync(dto.NewEmail, "Confirm your new email", html);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to queue change email confirmation to {Email}", dto.NewEmail);
            }
            return Ok(new SentResponse { Sent = true });
        }

        [HttpPost("change-email/confirm")]
        [Authorize]
        public async Task<IActionResult> ChangeEmailConfirm([FromBody] ChangeEmailConfirmDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            var result = await _userManager.ChangeEmailAsync(user, dto.NewEmail, dto.Token);
            if (!result.Succeeded) throw new BadRequestException(string.Join(", ", result.Errors.Select(e => e.Description)));
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
            if (user == null) throw new UnauthorizedAccessException();
            if (!user.MfaEnabled || string.IsNullOrWhiteSpace(user.MfaSecret)) throw new MfaNotInitializedException();
            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret)) throw new MfaNotInitializedException();
            var issuer = _configuration["Mfa:Issuer"] ?? _configuration["JWT:ValidIssuer"] ?? "AuthAPI";
            var otpauthUrl = _totp.GetOtpAuthUrl(secret, user.Email ?? user.UserName!, issuer);

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
            if (string.IsNullOrWhiteSpace(provided)) throw new BadRequestException("Refresh token is missing.");
            var ok = await _refreshTokenService.RevokeAsync(provided!, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", "manual");
            if (!ok) throw new NotFoundException("Refresh token not found or already revoked.");
            return Ok();
        }

        [HttpPost("request-password-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequestDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var resetKey1m = $"pwd-reset:1m:{dto.Email}";
            var resetKey1d = $"pwd-reset:1d:{dto.Email}";
            var allow1m = await _throttle.AllowAsync(resetKey1m, 1, TimeSpan.FromMinutes(1));
            var allow1d = await _throttle.AllowAsync(resetKey1d, 5, TimeSpan.FromDays(1));
            if (!allow1m || !allow1d) return Ok(new SentResponse { Sent = true });
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null || !user.EmailConfirmed || await _userManager.IsLockedOutAsync(user)) 
            {
                return Ok(new SentResponse { Sent = true });
            }
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
                _email.QueueSendAsync(user.Email!, "Password reset", html);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to queue password reset email to {Email}", dto.Email);
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
            if (user == null) throw new UserNotFoundException();
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
                    throw new BadRequestException("New password must not match your recent passwords.");
                }
            }
            var res = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
            if (!res.Succeeded) throw new BadRequestException(string.Join(", ", res.Errors.Select(e => e.Description)));
            user.TokenVersion += 1;
            await _userManager.UpdateAsync(user);
            await _refreshTokenService.RevokeAllForUserAsync(user.Id, "password-reset");
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
            var emailKey1m = $"email-confirm:1m:{dto.Email}";
            var emailKey1d = $"email-confirm:1d:{dto.Email}";
            var allow1m = await _throttle.AllowAsync(emailKey1m, 1, TimeSpan.FromMinutes(1));
            var allow1d = await _throttle.AllowAsync(emailKey1d, 5, TimeSpan.FromDays(1));
            if (!allow1m || !allow1d) return Ok(new SentResponse { Sent = true });
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Ok(new SentResponse { Sent = true });
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
                _email.QueueSendAsync(user.Email!, "Email confirmation", html);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to queue email confirmation request to {Email}", dto.Email);
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
            if (user == null) throw new UserNotFoundException("Invalid email.");
            if (user.EmailConfirmed) return Ok(new { emailConfirmed = true });
            if (string.IsNullOrWhiteSpace(dto.Token) || dto.Token.Length > 2048 || dto.Token.Any(char.IsWhiteSpace))
            {
                throw new InvalidTokenException("Invalid or expired confirmation token.");
            }
            try
            {
                var res = await _userManager.ConfirmEmailAsync(user, dto.Token);
                if (!res.Succeeded)
                {
                    throw new InvalidTokenException(string.Join(", ", res.Errors.Select(e => e.Description)));
                }
                return Ok(new EmailConfirmedResponse { EmailConfirmed = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during email confirmation for {Email}", dto.Email);
                throw new BadRequestException("Email confirmation failed. Please request a new token and try again.");
            }
        }

        [HttpPost("mfa/enroll/start")]
        [Authorize]
        public async Task<IActionResult> MfaEnrollStart()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            if (!user.MfaEnabled || string.IsNullOrWhiteSpace(user.MfaSecret)) throw new MfaNotInitializedException();
            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret)) throw new MfaNotInitializedException();
            var issuer = _configuration["Mfa:Issuer"] ?? _configuration["JWT:ValidIssuer"] ?? "AuthAPI";
            var otpauthUrl = _totp.GetOtpAuthUrl(secret, user.Email ?? user.UserName!, issuer);

            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(otpauthUrl, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeImage = qrCode.GetGraphic(20);
            return File(qrCodeImage, "image/png");
        }

        [HttpPost("mfa/enroll/confirm")]
        [Authorize]
        [EnableRateLimiting("otp")]
        public async Task<IActionResult> MfaEnrollConfirm([FromBody] MfaCodeDto dto)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            if (string.IsNullOrWhiteSpace(user.MfaSecret)) throw new MfaNotInitializedException();
            var secret = _protector.Unprotect(user.MfaSecret);
            if (string.IsNullOrWhiteSpace(secret)) throw new MfaNotInitializedException();
            if (!_totp.ValidateCode(secret, dto.Code, out var ts)) throw new InvalidMfaCodeException();
            user.MfaEnabled = true;
            user.MfaLastTimeStep = ts;
            await _userManager.UpdateAsync(user);
            var codes = await _recoveryCodes.GenerateAsync(user);
            return Ok(new MfaEnabledResponse { Enabled = true, RecoveryCodes = codes });
        }

        [HttpPost("mfa/disable")]
        [Authorize(Policy = AuthConstants.Policies.Mfa)]
        public async Task<IActionResult> MfaDisable()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            user.MfaEnabled = false;
            user.MfaSecret = null;
            user.MfaLastTimeStep = -1;
            var codes = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
            _db.UserRecoveryCodes.RemoveRange(codes);
            await _db.SaveChangesAsync();
            await _userManager.UpdateAsync(user);
            return Ok();
        }

        [HttpPost("mfa/recovery/regenerate")]
        [Authorize(Policy = AuthConstants.Policies.Mfa)]
        public async Task<IActionResult> RegenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) throw new UnauthorizedAccessException();
            var existing = _db.UserRecoveryCodes.Where(r => r.UserId == user.Id);
            _db.UserRecoveryCodes.RemoveRange(existing);
            await _db.SaveChangesAsync();
            var codes = await _recoveryCodes.GenerateAsync(user);
            return Ok(new RecoveryCodesResponse { RecoveryCodes = codes });
        }
    }
}