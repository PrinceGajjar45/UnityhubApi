using UnityHub.Core.Interface;
using UnityHub.Infrastructure.CommonModel;
using UnityHub.Infrastructure.Interface;

namespace UnityHub.Core.Services
{
    public class ServiceProviderService : IServiceProviderService
    {
        private readonly IServiceProviderRepository _serviceProviderRepository;
        public ServiceProviderService(IServiceProviderRepository serviceProviderRepository)
        {
            _serviceProviderRepository = serviceProviderRepository;
        }

        public async Task<Response> GetAllServiceProvider()
        {
            try
            {
                return await _serviceProviderRepository.GetAllServiceProvider();
            }
            catch (Exception ex)
            {
                return Response.Error(ex.Message);
            }
        }

        public async Task<Response> GetNearbyServiceProviders(decimal latitude, decimal longitude, double maxDistanceKm = 50)
        {
            try
            {
                return await _serviceProviderRepository.GetNearbyServiceProviders(latitude, longitude, maxDistanceKm);
            }
            catch (Exception ex)
            {
                return Response.Error(ex.Message);
            }
        }
    }
}
