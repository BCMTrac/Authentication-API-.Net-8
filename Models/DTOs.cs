using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace AuthenticationAPI.Models
{
    public class LoginModel : StrictDtoBase
    {
        [Required, StringLength(254)]
        public string Identifier { get; set; } = null!;

        [Required, StringLength(256, MinimumLength = 1)]
        public string Password { get; set; } = null!;

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
        [Required, StringLength(2048)] public string Token { get; set; } = string.Empty;
    }
    
    // Refresh token request (token optional: cookie can be used)
    public class RefreshRequest : StrictDtoBase
    {
        [StringLength(1024)]
        public string? RefreshToken { get; set; }
    }
    
    public class MfaCodeDto : StrictDtoBase
    {
        [Required, RegularExpression(@"^[0-9]{6}$")]
        public string Code { get; set; } = string.Empty;
    }

}
