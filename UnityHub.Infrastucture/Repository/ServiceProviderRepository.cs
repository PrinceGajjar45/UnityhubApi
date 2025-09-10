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
                var roleServiceProviders = await _userManager.GetUsersInRoleAsync(userRole);

                if (roleServiceProviders.Any())
                {
                    var response = Response.Success("Successfully retrieved all service providers");
                    response.Data = roleServiceProviders.ToList();
                    return response;
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

        public async Task<Response> GetNearbyServiceProviders(decimal latitude, decimal longitude, double maxDistanceKm = 50)
        {
            try
            {
                var userRole = "ServiceProvider";
                var serviceProviders = await _userManager.GetUsersInRoleAsync(userRole);

                if (!serviceProviders.Any())
                {
                    return Response.NotFound("No service providers found");
                }

                var nearbyProviders = serviceProviders
                    .Where(sp => sp.Latitude.HasValue && sp.Longitude.HasValue)
                    .Select(sp => new LocationBasedResponse
                    {
                        ServiceProvider = sp,
                        DistanceInKm = CalculateDistance(
                            (double)latitude,
                            (double)longitude,
                            (double)sp.Latitude.Value,
                            (double)sp.Longitude.Value)
                    })
                    .Where(x => x.DistanceInKm <= maxDistanceKm)
                    .OrderBy(x => x.DistanceInKm)
                    .ToList();

                if (!nearbyProviders.Any())
                {
                    return Response.NotFound($"No service providers found within {maxDistanceKm}km");
                }

                var response = Response.Success("Successfully retrieved nearby service providers");
                response.Data = nearbyProviders;
                return response;
            }
            catch (Exception ex)
            {
                return Response.Error($"Error retrieving nearby service providers: {ex.Message}");
            }
        }

        private static double CalculateDistance(double lat1, double lon1, double lat2, double lon2)
        {
            const double earthRadiusKm = 6371; // Earth's radius in kilometers

            var dLat = ToRad(lat2 - lat1);
            var dLon = ToRad(lon2 - lon1);

            lat1 = ToRad(lat1);
            lat2 = ToRad(lat2);

            var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                    Math.Sin(dLon / 2) * Math.Sin(dLon / 2) *
                    Math.Cos(lat1) * Math.Cos(lat2);
            var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));

            return earthRadiusKm * c;
        }

        private static double ToRad(double degrees)
        {
            return degrees * Math.PI / 180;
        }
    }
}
