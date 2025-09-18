using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationAPI.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
        public DbSet<IdempotencyRecord> IdempotencyRecords => Set<IdempotencyRecord>();
        public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
        public DbSet<ClientApp> ClientApps => Set<ClientApp>();
        public DbSet<UserRecoveryCode> UserRecoveryCodes => Set<UserRecoveryCode>();
        public DbSet<Session> Sessions => Set<Session>();
        public DbSet<Tenant> Tenants => Set<Tenant>();
        public DbSet<UserTenant> UserTenants => Set<UserTenant>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            
            builder.Entity<Tenant>(b =>
            {
                b.HasIndex(t => t.Subdomain).IsUnique();
                b.Property(t => t.Id).HasMaxLength(128);
            });

            
            builder.Entity<UserTenant>(b =>
            {
                b.HasKey(ut => ut.Id);
                b.HasIndex(ut => new { ut.UserId, ut.TenantId }).IsUnique();

                b.HasOne(ut => ut.User)
                    .WithMany(u => u.UserTenants)
                    .HasForeignKey(ut => ut.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                b.HasOne(ut => ut.Tenant)
                    .WithMany(t => t.UserTenants)
                    .HasForeignKey(ut => ut.TenantId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            
            builder.Entity<ApplicationUser>(b =>
            {
                b.Property(u => u.Id).HasMaxLength(128);
                b.Property(u => u.NormalizedUserName).HasMaxLength(128);
                b.Property(u => u.NormalizedEmail).HasMaxLength(128);
                
                b.Ignore(u => u.TenantId);
            });
            builder.Entity<IdentityRole>(b =>
            {
                b.Property(r => r.Id).HasMaxLength(128);
                b.Property(r => r.NormalizedName).HasMaxLength(128);
            });

            

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
                .OnDelete(DeleteBehavior.NoAction);

            
            builder.Entity<RefreshToken>(b =>
            {
                b.Property(r => r.TokenHash)
                    .HasMaxLength(64);
                b.Property(r => r.ReplacedByTokenHash)
                    .HasMaxLength(64);
            });

            
            builder.Entity<UserRecoveryCode>(b =>
            {
                b.Property(rc => rc.CodeHash)
                    .HasMaxLength(64);
            });

            
        }
    }
}