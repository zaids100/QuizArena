namespace QuizArena.DTOs;
public record RegisterDto(string Email, string Password, string? DisplayName);

public record LoginDto(string Email, string Password);
public record RefreshRequestDto(string RefreshToken);
public record RevokeDto(string RefreshToken);
public record GoogleSignInDto(string IdToken);
