using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Core.Interface
{
    public interface IServiceProviderService
    {
        Task<Response> GetAllServiceProvider();
        Task<Response> GetNearbyServiceProviders(decimal latitude, decimal longitude, double maxDistanceKm = 50);
    }
}
