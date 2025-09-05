using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<Permission> Permissions => Set<Permission>();
        public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
        public DbSet<IdempotencyRecord> IdempotencyRecords => Set<IdempotencyRecord>();
        public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
        public DbSet<ClientApp> ClientApps => Set<ClientApp>();
    public DbSet<UserRecoveryCode> UserRecoveryCodes => Set<UserRecoveryCode>();
        public DbSet<Session> Sessions => Set<Session>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<RolePermission>().HasKey(rp => new { rp.RoleId, rp.PermissionId });
            builder.Entity<RolePermission>()
                .HasOne(rp => rp.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(rp => rp.PermissionId);

            builder.Entity<Permission>().HasIndex(p => p.Name).IsUnique();

            builder.Entity<RefreshToken>()
                .HasIndex(r => new { r.UserId, r.TokenHash }).IsUnique();

            builder.Entity<IdempotencyRecord>()
                .HasIndex(i => i.CreatedUtc);

            builder.Entity<SigningKey>()
                .HasIndex(k => k.Kid).IsUnique();

            builder.Entity<ClientApp>()
                .HasIndex(c => c.Name).IsUnique();

            builder.Entity<UserRecoveryCode>()
                .HasIndex(rc => new { rc.UserId, rc.CodeHash }).IsUnique();

            builder.Entity<Session>()
                .HasIndex(s => new { s.UserId, s.CreatedUtc });
            builder.Entity<RefreshToken>()
                .HasOne(r => r.Session)
                .WithMany()
                .HasForeignKey(r => r.SessionId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
