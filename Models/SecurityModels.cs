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
    public string Algorithm { get; set; } = "HS256"; // future support for RSA/ECDSA
    [Required]
    public string Secret { get; set; } = string.Empty; // base64 encoded secret material
    public bool Active { get; set; } = true; // for signing new tokens
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RetiredUtc { get; set; }
}

public class ClientApp
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required, MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    [Required]
    public string SecretHash { get; set; } = string.Empty; // SHA256 hash of secret
    [MaxLength(400)]
    public string AllowedScopes { get; set; } = string.Empty; // space-delimited
    public bool Active { get; set; } = true;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
