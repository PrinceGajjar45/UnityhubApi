using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UnityHub.Core.Interface;
using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ServiceProviderController : ControllerBase
    {
        private readonly IServiceProviderService _serviceProviderService;

        public ServiceProviderController(IServiceProviderService serviceProviderService)
        {
            _serviceProviderService = serviceProviderService;
        }

        [HttpGet]
        [Authorize(Policy = "ServiceProviderOnly")]
        [Route("GetServiceProviderOnly")]
        public IActionResult GetServiceProviderOnly()
        {
            try
            {
                return Ok(new Response { Status = "Success", Message = "Welcome to the ServiceProviderOnly!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpGet]
        [Route("Get-all")]
        public async Task<ActionResult<Response>> GetAllServiceProvider()
        {
            try
            {
                var result = await _serviceProviderService.GetAllServiceProvider();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new Response { Status = "Error", Message = ex.Message });
            }
        }

        [HttpGet]
        [Route("Get-nearby")]
        public async Task<ActionResult<Response>> GetNearbyServiceProviders(
            [FromQuery] decimal latitude,
            [FromQuery] decimal longitude,
            [FromQuery] double maxDistanceKm = 50)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new Response { Status = "Error", Message = "Invalid input parameters" });
                }

                var result = await _serviceProviderService.GetNearbyServiceProviders(latitude, longitude, maxDistanceKm);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new Response { Status = "Error", Message = ex.Message });
            }
        }
    }
}
