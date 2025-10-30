using QuizArena.Models;
namespace QuizArena.Services;
public interface ITokenService
{
    Task<(string accessToken, string refreshToken, DateTimeOffset refreshTokenExpiresAt)> GenerateTokensAsync(ApplicationUser user, string createdByIp);
    Task<ApplicationUser?> ValidateRefreshTokenAsync(string refreshToken);
    Task<(string newAccessToken, string newRefreshToken, DateTimeOffset refreshTokenExpiresAt)> RefreshAsync(string refreshToken, string ipAddress);
    Task RevokeRefreshTokenAsync(string refreshToken, string ipAddress, string? reason = null);
}
