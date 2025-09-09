using AuthenticationAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Data
{
    // Separate application database for roles/permissions (tenant-aware elsewhere)
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Permission> Permissions => Set<Permission>();
        public DbSet<RolePermission> RolePermissions => Set<RolePermission>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Permissions
            builder.Entity<Permission>(b =>
            {
                b.HasIndex(p => p.Name).IsUnique();
            });

            // RolePermissions: composite PK and no FK to IdentityRole (lives in Auth DB)
            builder.Entity<RolePermission>(b =>
            {
                b.HasKey(rp => new { rp.RoleId, rp.PermissionId });
                b.Property(rp => rp.RoleId).HasMaxLength(128);
                b.HasOne(rp => rp.Permission)
                    .WithMany(p => p.RolePermissions)
                    .HasForeignKey(rp => rp.PermissionId)
                    .OnDelete(DeleteBehavior.Cascade);
                // Avoid mapping the navigation to IdentityRole since it's in a different DB
                b.Ignore(rp => rp.Role);
            });
        }
    }
}

