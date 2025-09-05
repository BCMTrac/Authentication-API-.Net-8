using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class UserRecoveryCode
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string UserId { get; set; } = null!;
        [Required]
        public string CodeHash { get; set; } = null!; // store hashed recovery code
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime? RedeemedUtc { get; set; }
        public string? RedeemedIp { get; set; }
    }
}
