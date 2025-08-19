using System.Threading.Tasks;
using UnityHub.Infrastructure.Models;
using Response = UnityHub.Infrastructure.Models.Response;

namespace UnityHub.Infrastructure.Interface
{
    public interface IAuthRepository
    {
        Task<Response> Login(LoginModel model);
        Task<Response> Register(RegisterModel model);
        Task<Response> VerifyTwoFactorCodeAsync(string email, string code);
        Task<Response> ForgotPassword(ForgotPassword email);
        Task<Response> ResetPassword(ResetPassword resetPassword);
    }
}
