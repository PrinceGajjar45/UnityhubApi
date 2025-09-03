using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UnityHub.API.Controllers
{
    [Authorize(policy: "AdminOnly")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [HttpGet("Dashboard")]
        public IActionResult GetAdminDashboard()
        {
            return Ok("Welcome to the Admin Dashboard!");
        }
    }
}
