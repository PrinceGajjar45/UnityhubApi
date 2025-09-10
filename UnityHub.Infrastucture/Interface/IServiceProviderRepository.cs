using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Infrastructure.Interface
{
    public interface IServiceProviderRepository
    {
        Task<Response> GetAllServiceProvider();
        Task<Response> GetNearbyServiceProviders(decimal latitude, decimal longitude, double maxDistanceKm = 50);
    }
}
