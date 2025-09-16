using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthenticationAPI.Models
{
    public class UserTenant
    {
        [Key]
        public Guid Id { get; set; } = Guid.NewGuid();

        [Required]
        public string UserId { get; set; } = null!;
        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; } = null!;

        [Required]
        public string TenantId { get; set; } = null!;
        [ForeignKey(nameof(TenantId))]
        public Tenant Tenant { get; set; } = null!;

        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    }
}
