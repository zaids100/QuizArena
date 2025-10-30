using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using QuizArena.Models;
using QuizArena.Services;
using QuizArena.DTOs;

namespace QuizArena.Controllers;
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<ApplicationUser> um, SignInManager<ApplicationUser> sm, ITokenService ts, IConfiguration cfg)
    {
        _userManager = um;
        _signInManager = sm;
        _tokenService = ts;
        _configuration = cfg;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var user = new ApplicationUser { UserName = dto.Email, Email = dto.Email, DisplayName = dto.DisplayName };
        var res = await _userManager.CreateAsync(user, dto.Password);
        if (!res.Succeeded) return BadRequest(res.Errors);

        //optionally assign default role
        await _userManager.AddToRoleAsync(user, "USER");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var (access, refresh, expires) = await _tokenService.GenerateTokensAsync(user, ip);
        Console.WriteLine("Token Generated");

        return Ok(new { accessToken = access, refreshToken = refresh, refreshTokenExpiresAt = expires });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Unauthorized("Invalid credentials");

        var res = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);
        if (!res.Succeeded) return Unauthorized("Invalid credentials");

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var (access, refresh, expires) = await _tokenService.GenerateTokensAsync(user, ip);
        user.LastLogin = DateTimeOffset.UtcNow;
        await _userManager.UpdateAsync(user);

        return Ok(new { accessToken = access, refreshToken = refresh, refreshTokenExpiresAt = expires });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto dto)
    {
        try
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var (newAccess, newRefresh, expires) = await _tokenService.RefreshAsync(dto.RefreshToken, ip);
            return Ok(new { accessToken = newAccess, refreshToken = newRefresh, refreshTokenExpiresAt = expires });
        }
        catch (SecurityTokenException)
        {
            return Unauthorized();
        }
    }

    [HttpPost("revoke")]
    [Authorize]
    public async Task<IActionResult> Revoke([FromBody] RevokeDto dto)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        await _tokenService.RevokeRefreshTokenAsync(dto.RefreshToken, ip, "revoked by user");
        return NoContent();
    }

    // Google sign-in using id_token from client
    // Client: signs in with Google SDK and sends id_token to backend
    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Missing authorization code");

        // Exchange code for tokens
        using var httpClient = new HttpClient();

        var tokenRequest = new Dictionary<string, string>
    {
        { "code", code },
        { "client_id", _configuration["Authentication:Google:ClientId"] },
        { "client_secret", _configuration["Authentication:Google:ClientSecret"] },
        { "redirect_uri", "https://localhost:7158/api/auth/google/callback" },
        { "grant_type", "authorization_code" }
    };

        var tokenResponse = await httpClient.PostAsync("https://oauth2.googleapis.com/token",
            new FormUrlEncodedContent(tokenRequest));

        var json = await tokenResponse.Content.ReadAsStringAsync();

        if (!tokenResponse.IsSuccessStatusCode)
            return BadRequest("Token exchange failed: " + json);

        var tokenData = System.Text.Json.JsonDocument.Parse(json).RootElement;

        var idToken = tokenData.GetProperty("id_token").GetString();

        // Validate ID token
        GoogleJsonWebSignature.Payload payload;
        try
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { _configuration["Authentication:Google:ClientId"] }
            };
            payload = await GoogleJsonWebSignature.ValidateAsync(idToken, settings);
        }
        catch (Exception ex)
        {
            return BadRequest("Invalid Google ID token: " + ex.Message);
        }

        // User info
        var googleId = payload.Subject;
        var email = payload.Email;

        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.GoogleId == googleId || u.Email == email);

        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                GoogleId = googleId,
                DisplayName = payload.Name
            };
            var createRes = await _userManager.CreateAsync(user);
            if (!createRes.Succeeded) return BadRequest(createRes.Errors);
            await _userManager.AddToRoleAsync(user, "User");
        }
        else if (user.GoogleId == null)
        {
            user.GoogleId = googleId;
            await _userManager.UpdateAsync(user);
        }

        // Generate your app's tokens
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var (access, refresh, expires) = await _tokenService.GenerateTokensAsync(user, ip);

        // Optionally redirect to frontend with token
        var redirectUrl = $"http://127.0.0.1:5500/success.html?accessToken={access}";
        return Redirect(redirectUrl);
    }

}
