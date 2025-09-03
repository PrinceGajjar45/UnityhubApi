using UnityHub.Core.CommonModel;
using UnityHub.Core.Models;


namespace UnityHub.Core.Interface
{
    public interface IAuthService
    {
        Task<CustomApiResponse<UserBasicDetails>> RegisterAsync(RegisterModel model);
        Task<CustomApiResponse<UserBasicDetails>> LoginAsync(LoginModel model);
        Task<CustomApiResponse<object>> VerifyTwoFactorCodeAsync(string email, string code);
        Task<CustomApiResponse<object>> ForgotPassword(ForgotPassword email);
        Task<CustomApiResponse<object>> ResetPassword(ResetPassword resetPassword);
        Task<CustomApiResponse<object>> ChangeUserPassword(ChangeUserPassword changeUserPassword);
        Task<CustomApiResponse<object>> ReSentVerificationCode(ReSentVerificationCode reSentVerification);
        Task<CustomApiResponse<object>> UpdateUserProfile(UpdateUserProfile updateUserProfile);
        Task<CustomApiResponse<UserBasicDetails>> GetUserProfileAsync(string email); // Get user profile by UserId
    }
}
