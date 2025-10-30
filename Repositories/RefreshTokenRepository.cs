using Microsoft.EntityFrameworkCore;
using QuizArena.Data;
using QuizArena.Models;

namespace QuizArena.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _db;

    public RefreshTokenRepository(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task AddAsync(RefreshToken token)
    {
        await _db.RefreshTokens.AddAsync(token);
    }

    public async Task<RefreshToken?> GetByHashAsync(string tokenHash)
    {
        return await _db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
    }

    public async Task SaveChangesAsync()
    {
        await _db.SaveChangesAsync();
    }
}
