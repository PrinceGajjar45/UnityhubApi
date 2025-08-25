using UnityHub.Core.Models;
using UnityHub.Core.ServiceModel;

namespace UnityHub.Core.Interface
{
    public interface IAuthService
    {
        Task<Response> RegisterAsync(RegisterModel model);
        Task<Response> LoginAsync(LoginModel model);
        Task<Response> VerifyTwoFactorCodeAsync(string email, string code);
        Task<Response> ForgotPassword(ForgotPassword email);
        Task<Response> ResetPassword(ResetPassword resetPassword);
        Task<Response> ChangeUserPassword(ChangeUserPassword changeUserPassword);
        Task<Response> ReSentVerificationCode(ReSentVerificationCode reSentVerification);

    }
}
