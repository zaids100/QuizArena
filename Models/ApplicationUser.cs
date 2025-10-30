using Microsoft.AspNetCore.Identity;

namespace QuizArena.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? DisplayName { get; set; }
        public string? GoogleId { get; set; }  // stores Google 'sub' identifier; nullable
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        // Add this 👇
        public DateTimeOffset? LastLogin { get; set; }
    }
}
