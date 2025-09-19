using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models;

public class SigningKey
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required]
    [MaxLength(40)]
    public string Kid { get; set; } = string.Empty; // key identifier in JWT header
    [Required]
    public string Algorithm { get; set; } = "RS256";
    [Required]
    public string Secret { get; set; } = string.Empty;
    public string? PublicKey { get; set; }
    public bool Active { get; set; } = true; // for signing new tokens
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RetiredUtc { get; set; }
}
