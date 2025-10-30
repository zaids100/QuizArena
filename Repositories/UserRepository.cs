using Microsoft.AspNetCore.Identity;
using QuizArena.Models;

namespace QuizArena.Repositories;

public class UserRepository : IUserRepository
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserRepository(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public IQueryable<ApplicationUser> Users => _userManager.Users;

    public async Task<IList<string>> GetRolesAsync(ApplicationUser user)
    {
        return await _userManager.GetRolesAsync(user);
    }

    public async Task<ApplicationUser?> FindByIdAsync(string id)
    {
        return await _userManager.FindByIdAsync(id);
    }

    public async Task<ApplicationUser?> FindByEmailAsync(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    public async Task<IdentityResult> CreateAsync(ApplicationUser user, string? password = null)
    {
        if (password == null)
            return await _userManager.CreateAsync(user);
        return await _userManager.CreateAsync(user, password);
    }

    public async Task<IdentityResult> UpdateAsync(ApplicationUser user)
    {
        return await _userManager.UpdateAsync(user);
    }

    public async Task<IdentityResult> AddToRoleAsync(ApplicationUser user, string role)
    {
        return await _userManager.AddToRoleAsync(user, role);
    }
}
