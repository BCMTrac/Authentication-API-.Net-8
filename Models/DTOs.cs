using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace AuthenticationAPI.Models
{
    public class RegisterModel : StrictDtoBase
    {
        [Required]
        [RegularExpression(@"^[\p{L}0-9._-]{3,50}$", ErrorMessage = "Username must be 3-50 chars: letters, numbers, . _ -")]
        public string Username { get; set; } = null!;

        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = null!;

        [Required, StringLength(256, MinimumLength = 12)]
        public string Password { get; set; } = null!;

        [StringLength(100, MinimumLength = 2)]
        public string? FullName { get; set; }

        // If used for MFA later; format E.164 (+ plus digits), 8-15 digits total
        [RegularExpression(@"^\+[1-9][0-9]{7,14}$", ErrorMessage = "Phone must be E.164 format e.g. +15551234567")]
        public string? Phone { get; set; }
    }

    public class LoginModel : StrictDtoBase
    {
        // Accept email or username
        [Required, StringLength(254)]
        public string Identifier { get; set; } = null!;

        [Required, StringLength(256, MinimumLength = 1)]
        public string Password { get; set; } = null!;

        // 6-digit numeric for TOTP step-up
        [RegularExpression(@"^[0-9]{6}$")]
        public string? MfaCode { get; set; }
    }

    public class ChangePasswordDto : StrictDtoBase
    {
        [Required] public string CurrentPassword { get; set; } = string.Empty;
        [Required, StringLength(256, MinimumLength = 12)] public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangeEmailStartDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)] public string NewEmail { get; set; } = string.Empty;
    }

    public class ChangeEmailConfirmDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)] public string NewEmail { get; set; } = string.Empty;
        [Required, StringLength(256)] public string Token { get; set; } = string.Empty;
    }
    
    // Refresh token request
    public class RefreshRequest : StrictDtoBase
    {
        [Required, StringLength(1024)]
        public string RefreshToken { get; set; } = null!;
    }
    
    // Password reset request
    public class PasswordResetRequestDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = string.Empty;
    }
    
    public class PasswordResetConfirmDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = string.Empty;
        [Required, StringLength(256)]
        public string Token { get; set; } = string.Empty;
        [Required, StringLength(256, MinimumLength = 12)]
        public string NewPassword { get; set; } = string.Empty;
    }
    
    // Email confirmation request
    public class EmailRequestDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = string.Empty;
    }
    public class EmailConfirmDto : StrictDtoBase
    {
        [Required, EmailAddress, StringLength(254)]
        public string Email { get; set; } = string.Empty;
        [Required, StringLength(256)]
        public string Token { get; set; } = string.Empty;
    }
    
    // MFA code DTO
    public class MfaCodeDto : StrictDtoBase
    {
        [Required, RegularExpression(@"^[0-9]{6}$")]
        public string Code { get; set; } = string.Empty;
    }
}
