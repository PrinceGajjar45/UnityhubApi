using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UnityHub.API.Controllers
{
    [Authorize(policy: "ServiceProviderOnly")]
    [Route("api/[controller]")]
    [ApiController]
    public class ServiceProviderController : ControllerBase
    {
        [HttpGet("GetServiceProviderOnly")]
        public IActionResult GetAllServiceProvider()
        {
            return Ok("Welcome to the ServiceProviderOnly!");
        }
    }
}
