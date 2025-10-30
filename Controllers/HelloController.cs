using Microsoft.AspNetCore.Mvc;

namespace QuizArena.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HelloController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Hello from QuizArena API! 🚀");
        }

        [HttpGet("{name}")]
        public IActionResult GetPersonalized(string name)
        {
            return Ok($"Hello, {name}! Welcome to QuizArena API 🎯");
        }
    }
}
