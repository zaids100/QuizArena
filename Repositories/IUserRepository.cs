using Microsoft.AspNetCore.Identity;
using QuizArena.Models;

namespace QuizArena.Repositories;

public interface IUserRepository
{
    Task<IList<string>> GetRolesAsync(ApplicationUser user);
    Task<ApplicationUser?> FindByIdAsync(string id);
    Task<ApplicationUser?> FindByEmailAsync(string email);
    IQueryable<ApplicationUser> Users { get; }
    Task<IdentityResult> CreateAsync(ApplicationUser user, string? password = null);
    Task<IdentityResult> UpdateAsync(ApplicationUser user);
    Task<IdentityResult> AddToRoleAsync(ApplicationUser user, string role);
}
