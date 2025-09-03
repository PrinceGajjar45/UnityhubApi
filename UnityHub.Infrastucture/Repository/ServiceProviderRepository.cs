using UnityHub.Infrastructure.Data;

namespace UnityHub.Infrastructure.Repository
{
    public class ServiceProviderRepository
    {
        private readonly ApplicationDbContext _context;

        public ServiceProviderRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        //public async Task<bool> ConvertToServiceProviderAsync(string userId, string businessName, string businessDescription)
        //{
        //    var user = await _context.Users
        //        .Include(u => u.ServiceProvider)
        //        .FirstOrDefaultAsync(u => u.Id == userId);

        //    if (user == null || user.ServiceProvider != null)
        //        return false;

        //    user.IsServiceProvider = true;

        //    var serviceProvider = new ServiceProvider
        //    {
        //        UserId = userId,
        //        BusinessName = businessName,
        //        BusinessDescription = businessDescription
        //    };

        //    serviceProvider.UpdateFromUserProfile(); // Copy user location to business location

        //    _context.ServiceProviders.Add(serviceProvider);
        //    await _context.SaveChangesAsync();

        //    return true;
        //}

        //public async Task<bool> AddSkillToProviderAsync(int providerId, int categoryId, int yearsOfExperience = 0, string certification = null,
        //    decimal hourlyRate = 0, bool isPrimary = false)
        //{
        //    var skill = new ServiceProviderSkill
        //    {
        //        ServiceProviderId = providerId,
        //        ServiceCategoryId = categoryId,
        //        YearsOfExperience = yearsOfExperience,
        //        Certification = certification,
        //        HourlyRate = hourlyRate,
        //        IsPrimarySkill = isPrimary
        //    };

        //    _context.ServiceProviderSkills.Add(skill);
        //    await _context.SaveChangesAsync();

        //    return true;
        //}

        //public async Task<List<ServiceProvider>> FindNearbyProvidersAsync(decimal latitude, decimal longitude, double maxDistanceKm, int? categoryId = null)
        //{
        //    var providers = await _context.ServiceProviders
        //        .Include(sp => sp.User)
        //        .Include(sp => sp.Skills)
        //        .ThenInclude(s => s.ServiceCategory)
        //        .Where(sp => sp.IsVerified)
        //        .ToListAsync();

        //    // Filter by distance and category
        //    var nearbyProviders = providers.Where(sp =>
        //    {
        //        var distance = CalculateDistance(
        //            latitude, longitude,
        //            sp.BusinessLatitude, sp.BusinessLongitude
        //        );
        //        return distance <= maxDistanceKm;
        //    });

        //    if (categoryId.HasValue)
        //    {
        //        nearbyProviders = nearbyProviders.Where(sp =>
        //            sp.Skills.Any(s => s.ServiceCategoryId == categoryId.Value));
        //    }

        //    return nearbyProviders.ToList();
        //}

        //private double CalculateDistance(decimal lat1, decimal lon1, decimal lat2, decimal lon2)
        //{
        //    // Haversine formula implementation
        //    const double R = 6371; // Earth radius in km
        //    var dLat = ToRadians((double)(lat2 - lat1));
        //    var dLon = ToRadians((double)(lon2 - lon1));

        //    var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
        //            Math.Cos(ToRadians((double)lat1)) * Math.Cos(ToRadians((double)lat2)) *
        //            Math.Sin(dLon / 2) * Math.Sin(dLon / 2);

        //    var c = 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
        //    return R * c;
        //}

        //private double ToRadians(double angle) => angle * (Math.PI / 180);
    }
}
