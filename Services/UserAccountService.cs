using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Services
{
    public class UserAccountService : IUserAccountService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private readonly IConfiguration _configuration;

        public UserAccountService(
            UserManager<ApplicationUser> userManager, 
            ApplicationDbContext db, 
            IPasswordHasher<ApplicationUser> passwordHasher,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _db = db;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
        }

        public async Task ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword)
        {
            var reuseWindow = _configuration.GetValue<int>("PasswordHistory:ReuseWindowCount", 5);
            var minAgeHours = _configuration.GetValue<int>("PasswordHistory:MinAgeHours", 24);

            var recentHashes = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedUtc).Take(reuseWindow).ToListAsync();

            foreach (var ph in recentHashes)
            {
                var verdict = _passwordHasher.VerifyHashedPassword(user, ph.Hash, newPassword);
                if (verdict == PasswordVerificationResult.Success)
                {
                    throw new BadRequestException("New password must not match your recent passwords.");
                }
            }

            if (minAgeHours > 0)
            {
                var lastChange = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedUtc).FirstOrDefaultAsync();
                if (lastChange != null && (System.DateTime.UtcNow - lastChange.CreatedUtc).TotalHours < minAgeHours)
                {
                    throw new BadRequestException("Password was changed recently. Try again later.");
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
            {
                throw new BadRequestException(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            await _db.Entry(user).ReloadAsync();
            if (!string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                _db.PasswordHistory.Add(new PasswordHistory { UserId = user.Id, Hash = user.PasswordHash });
                var keepCount = _configuration.GetValue<int>("PasswordHistory:KeepCount", 12);
                var toRemove = await _db.PasswordHistory.Where(ph => ph.UserId == user.Id)
                    .OrderByDescending(ph => ph.CreatedUtc).Skip(keepCount).ToListAsync();
                if (toRemove.Any())
                {
                    _db.PasswordHistory.RemoveRange(toRemove);
                }
                await _db.SaveChangesAsync();
            }
        }
    }
}