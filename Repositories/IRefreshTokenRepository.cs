using QuizArena.Models;

namespace QuizArena.Repositories;

public interface IRefreshTokenRepository
{
    Task AddAsync(RefreshToken token);
    Task<RefreshToken?> GetByHashAsync(string tokenHash);
    Task SaveChangesAsync();
}
