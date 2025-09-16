using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace AuthenticationAPI.Services
{
    public interface IUserAccountService
    {
        Task ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword);
    }
}
