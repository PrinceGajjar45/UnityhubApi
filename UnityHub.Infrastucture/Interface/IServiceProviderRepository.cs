using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Infrastructure.Interface
{
    public interface IServiceProviderRepository
    {
        Task<Response> GetAllServiceProvider();
    }
}
