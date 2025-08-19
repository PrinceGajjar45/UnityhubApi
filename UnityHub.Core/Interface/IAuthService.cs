using Microsoft.AspNetCore.Mvc;
using UnityHub.Core.ServiceModel;
using System.Threading.Tasks;
using UnityHub.Core.Models;

namespace UnityHub.Core.Interface
{
    public interface IAuthService
    {
        Task<Response> RegisterAsync(RegisterModel model);
        Task<Response> LoginAsync(LoginModel model);
        Task<Response> VerifyTwoFactorCodeAsync(string email, string code);
        Task<Response> ForgotPassword(ForgotPassword email);
        Task<Response> ResetPassword(ResetPassword resetPassword);
    }
}
