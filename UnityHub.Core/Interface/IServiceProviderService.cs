using UnityHub.Core.CommonModel;

namespace UnityHub.Core.Interface
{
    public interface IServiceProviderService
    {
        Task<Response> GetAllServiceProvider();
    }
}
