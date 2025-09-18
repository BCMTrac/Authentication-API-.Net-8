using AuthenticationAPI.Data;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationAPI.Exceptions;

namespace AuthenticationAPI.Services
{
    public class UserAccountService : IUserAccountService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserAccountService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword)
        {
            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
            {
                throw new BadRequestException(string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
    }
}