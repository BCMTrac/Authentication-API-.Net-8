using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class Tenant
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [Required]
        [MaxLength(100)]
        public string CompanyName { get; set; } = string.Empty;

        [Required]
        [MaxLength(50)]
        public string Subdomain { get; set; } = string.Empty;

        public bool MfaRequired { get; set; } = false;

        public string Plan { get; set; } = "Starter";

        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public ICollection<UserTenant> UserTenants { get; set; } = new List<UserTenant>();
    }
}
