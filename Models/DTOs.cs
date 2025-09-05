using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class RegisterModel
    {
        [Required]
        public string Username { get; set; } = null!;

        [EmailAddress]
        [Required]
        public string Email { get; set; } = null!;

        [Required]
        public string Password { get; set; } = null!;
    }

    public class LoginModel
    {
        [Required]
        public string Username { get; set; } = null!;

        [Required]
        public string Password { get; set; } = null!;
    public string? MfaCode { get; set; }
    }

    public class ChangePasswordDto
    {
        [Required] public string CurrentPassword { get; set; } = string.Empty;
        [Required] public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangeEmailStartDto
    {
        [Required, EmailAddress] public string NewEmail { get; set; } = string.Empty;
    }

    public class ChangeEmailConfirmDto
    {
        [Required, EmailAddress] public string NewEmail { get; set; } = string.Empty;
        [Required] public string Token { get; set; } = string.Empty;
    }
    
    // Refresh token request
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; } = null!;
    }
    
    // Password reset request
    public class PasswordResetRequestDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
    
    public class PasswordResetConfirmDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Token { get; set; } = string.Empty;
        [Required]
        public string NewPassword { get; set; } = string.Empty;
    }
    
    // Email confirmation request
    public class EmailRequestDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
    public class EmailConfirmDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Token { get; set; } = string.Empty;
    }
    
    // MFA code DTO
    public class MfaCodeDto
    {
        [Required]
        public string Code { get; set; } = string.Empty;
    }
}
