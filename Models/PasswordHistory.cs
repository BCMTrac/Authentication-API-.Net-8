using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models;

public class PasswordHistory
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required]
    public string UserId { get; set; } = null!;
    // Store the password hash payload as produced by the IPasswordHasher (Argon2 JSON)
    [Required]
    [MaxLength(4000)]
    public string Hash { get; set; } = null!;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

