using UnityHub.Core.CommonModel;
using UnityHub.Core.Interface;
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
                var response = await _serviceProviderRepository.GetAllServiceProvider();
                if (response != null)
                {
                    return Response.Success("Successfully retrieved all service providers");
                    //.WithUserData((ApplicationUser)roleServiceProviders);
                }
                return Response.Success("Successfully retrieved all service providers");
            }
            catch (Exception ex)
            {
                return Response.Error(ex.Message);
            }
        }
    }
}
