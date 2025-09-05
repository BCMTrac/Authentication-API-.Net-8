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
}
