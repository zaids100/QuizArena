using DotNetEnv;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using QuizArena.Data;
using QuizArena.Models;
using QuizArena.Services;
using QuizArena.Repositories;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// =======================================================
// 🔹 Load environment variables from .env file (development only)
// =======================================================
if (builder.Environment.IsDevelopment())
{
    var envFile = Path.Combine(Directory.GetCurrentDirectory(), ".env");
    if (File.Exists(envFile))
    {
        DotNetEnv.Env.Load(envFile);
        Console.WriteLine($"✅ .env file loaded successfully from {envFile}");

        var envVars = Environment.GetEnvironmentVariables();
        foreach (System.Collections.DictionaryEntry envVar in envVars)
        {
            var key = envVar.Key.ToString()?.Replace("__", ":");
            if (key != null)
                builder.Configuration[key] = envVar.Value?.ToString();
        }
    }
    else
    {
        Console.WriteLine($"⚠️ .env file not found at {envFile}");
    }
}

var configuration = builder.Configuration;

// =======================================================
// 🔹 Log critical configuration values
// =======================================================
Console.WriteLine("\n=== Critical Configuration Values ===");
var criticalKeys = new[]
{
    "ConnectionStrings:DbConnectionString",
    "Jwt:Secret",
    "Jwt:Issuer",
    "Jwt:Audience",
    "Authentication:Google:ClientId",
    "Authentication:Google:ClientSecret",
    "ASPNETCORE_ENVIRONMENT"
};

foreach (var key in criticalKeys)
{
    var value = configuration[key];
    Console.WriteLine($"{key} = {(key.Contains("Secret") ? "[MASKED]" : value ?? "NOT SET")}");
}
Console.WriteLine("=================================\n");

var connectionString = configuration["ConnectionStrings:DbConnectionString"]
    ?? throw new InvalidOperationException("Database connection string is not configured");

var jwtSecret = configuration["Jwt:Secret"]
    ?? throw new InvalidOperationException("JWT Secret is not configured");

Console.WriteLine($"Loaded environment: {builder.Environment.EnvironmentName}");
Console.WriteLine($"Connection String configured: {!string.IsNullOrEmpty(connectionString)}");
Console.WriteLine($"JWT Secret configured: {!string.IsNullOrEmpty(jwtSecret)}");

// =======================================================
// 🔹 Add services
// =======================================================

// ✅ DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        connectionString,
        sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5, // number of retry attempts
                maxRetryDelay: TimeSpan.FromSeconds(10), // delay between retries
                errorNumbersToAdd: null // retry all transient errors
            );
        }
    ));


// ✅ Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ✅ JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = configuration["Jwt:Issuer"] ?? "QuizArena",
        ValidateAudience = true,
        ValidAudience = configuration["Jwt:Audience"] ?? "QuizArenaClients",
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
        ValidateLifetime = true
    };
});

// ✅ Token Settings
builder.Services.Configure<TokenSettings>(options =>
{
    options.Secret = configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT Secret is not configured");
    options.Issuer = configuration["Jwt:Issuer"] ?? "QuizArena";
    options.Audience = configuration["Jwt:Audience"] ?? "QuizArenaClients";
    options.AccessTokenExpirationMinutes = 15;
    options.RefreshTokenExpirationDays = 30;
});

// Repositories
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUserRepository, UserRepository>();

builder.Services.AddScoped<ITokenService, TokenService>();

// ✅ CORS for local frontend (e.g. index.html running on http://localhost:5500)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:5500")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// ✅ Other core services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// =======================================================
// 🔹 Build the app
// =======================================================
var app = builder.Build();

// =======================================================
// 🔹 Middleware pipeline (order matters!)
// =======================================================

// Seed roles on startup
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    await DbSeeder.SeedRolesAsync(roleManager);
}

// ✅ Swagger (only in dev)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ✅ HTTPS redirection
app.UseHttpsRedirection();

// ✅ CORS (must be before authentication)
app.UseCors("AllowLocalFrontend");

// ✅ Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// ✅ Map controllers
app.MapControllers();

app.Run();
