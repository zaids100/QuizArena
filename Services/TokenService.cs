using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using QuizArena.Models;
using QuizArena.Services;
using QuizArena.Repositories;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace QuizArena.Services;
public class TokenSettings
{
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public string Secret { get; set; } = null!;
    public int AccessTokenExpirationMinutes { get; set; } = 15;
    public int RefreshTokenExpirationDays { get; set; } = 30;
}

public class TokenService : ITokenService
{
    private readonly TokenSettings _settings;
    private readonly IRefreshTokenRepository _refreshRepo;
    private readonly IUserRepository _userRepo;

    public TokenService(IOptions<TokenSettings> settings, IRefreshTokenRepository refreshRepo, IUserRepository userRepo)
    {
        _settings = settings.Value;
        _refreshRepo = refreshRepo;
        _userRepo = userRepo;
    }

    public async Task<(string accessToken, string refreshToken, DateTimeOffset refreshTokenExpiresAt)> GenerateTokensAsync(ApplicationUser user, string createdByIp)
    {
        var accessToken = await GenerateJwtTokenAsync(user);
        var (refreshToken, refreshTokenExpiresAt, refreshTokenHash) = CreateRefreshTokenAndHash();

        var dbToken = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            ExpiresAt = refreshTokenExpiresAt,
            CreatedAt = DateTimeOffset.UtcNow,
            CreatedByIp = createdByIp
        };

        await _refreshRepo.AddAsync(dbToken);
        await _refreshRepo.SaveChangesAsync();

        return (accessToken, refreshToken, refreshTokenExpiresAt);
    }

    private (string token, DateTimeOffset expiresAt, string tokenHash) CreateRefreshTokenAndHash()
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        var token = Convert.ToBase64String(randomBytes);
        var expires = DateTimeOffset.UtcNow.AddDays(_settings.RefreshTokenExpirationDays);
        var tokenHash = ComputeSha256Hash(token);
        return (token, expires, tokenHash);
    }

    private static string ComputeSha256Hash(string raw)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes); // .NET 5+; if older, use BitConverter.ToString(...).Replace("-","")
    }

    private async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new Claim("displayName", user.DisplayName ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

    var roles = await _userRepo.GetRolesAsync(user);
        foreach (var role in roles) claims.Add(new Claim(ClaimTypes.Role, role));

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.AccessTokenExpirationMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<ApplicationUser?> ValidateRefreshTokenAsync(string refreshToken)
    {
        var hash = ComputeSha256Hash(refreshToken);
    var token = await _refreshRepo.GetByHashAsync(hash);

    if (token == null || !token.IsActive) return null;

    var user = await _userRepo.FindByIdAsync(token.UserId);
    return user;
    }

    public async Task<(string newAccessToken, string newRefreshToken, DateTimeOffset refreshTokenExpiresAt)> RefreshAsync(string refreshToken, string ipAddress)
    {
        var hash = ComputeSha256Hash(refreshToken);
        var tokenEntity = await _refreshRepo.GetByHashAsync(hash);

        if (tokenEntity == null || !tokenEntity.IsActive)
            throw new SecurityTokenException("Invalid refresh token");

        // rotate: revoke current and create new
        tokenEntity.RevokedAt = DateTimeOffset.UtcNow;
        tokenEntity.RevokedByIp = ipAddress;

        var user = await _userRepo.FindByIdAsync(tokenEntity.UserId) ?? throw new Exception("User not found");

        var (newRefreshPlain, newExpires, newHash) = CreateRefreshTokenAndHash();

        var newDbToken = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newHash,
            ExpiresAt = newExpires,
            CreatedAt = DateTimeOffset.UtcNow,
            CreatedByIp = ipAddress,
            ReplacedByTokenHash = tokenEntity.TokenHash
        };

        await _refreshRepo.AddAsync(newDbToken);
        await _refreshRepo.SaveChangesAsync();

        var newAccess = await GenerateJwtTokenAsync(user);
        return (newAccess, newRefreshPlain, newExpires);
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken, string ipAddress, string? reason = null)
    {
        var hash = ComputeSha256Hash(refreshToken);
        var tok = await _refreshRepo.GetByHashAsync(hash);
        if (tok == null) return;
        tok.RevokedAt = DateTimeOffset.UtcNow;
        tok.RevokedByIp = ipAddress;
        tok.ReasonRevoked = reason;
        await _refreshRepo.SaveChangesAsync();
    }
}
