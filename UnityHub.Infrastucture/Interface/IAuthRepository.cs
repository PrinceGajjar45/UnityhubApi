using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Infrastructure.Interface
{
    public interface IAuthRepository
    {
        Task<Response> Login(LoginModel model);
        Task<Response> Register(RegisterModel model);
        Task<Response> ForgotPassword(ForgotPassword email);
        Task<Response> ResetPassword(ResetPassword resetPassword);
        Task<Response> ChangeUserPassword(ChangeUserPassword changeUserPassword);
        Task<Response> ReSentVerificationCode(ReSentVerificationCode reSentVerification);
        Task<Response> UpdateUserProfile(UpdateUserProfile updateUserProfile);
        Task<Response> VerifyTwoFactorCodeAsync(string email, string code);
        Task<Response> GetUserProfileAsync(string email);
        Task<Response> GetAllRoleNamesAsync();
    }
}
