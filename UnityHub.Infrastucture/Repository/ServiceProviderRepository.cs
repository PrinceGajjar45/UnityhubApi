using UnityHub.Infrastructure.CommonModel;
using UnityHub.Infrastructure.Data;
using UnityHub.Infrastructure.Interface;

namespace UnityHub.Infrastructure.Repository
{
    public class ServiceProviderRepository : IServiceProviderRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> _userManager;
        public ServiceProviderRepository(ApplicationDbContext context,
                        Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }

        public async Task<Response> GetAllServiceProvider()
        {
            try
            {
                var userRole = "ServiceProvider";

                // Get users in ServiceProvider role (never returns null)
                var roleServiceProviders = await _userManager.GetUsersInRoleAsync(userRole);


                if (roleServiceProviders.Any())
                {
                    return Response.Success("Successfully retrieved all service providers")
                        .WithUserData((ApplicationUser)roleServiceProviders);
                }
                else
                {
                    return Response.NotFound("No service providers found");
                }
            }
            catch (Exception ex)
            {
                return Response.Error($"Error retrieving service providers: {ex.Message}");
            }
        }
    }
}
