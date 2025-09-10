using UnityHub.Infrastructure.Data;

namespace UnityHub.Infrastructure.CommonModel
{
    public class LocationBasedResponse
    {
        public ApplicationUser ServiceProvider { get; set; }
        public double DistanceInKm { get; set; }
    }
}