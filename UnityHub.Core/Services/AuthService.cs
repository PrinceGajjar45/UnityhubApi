using UnityHub.Core.CommonModel;
using UnityHub.Core.Interface;
using UnityHub.Core.Models;
using UnityHub.Infrastructure.Interface;
using InfrastructureChangeUserPassword = UnityHub.Infrastructure.CommonModel.ChangeUserPassword;
using InfrastructureForgotPassword = UnityHub.Infrastructure.CommonModel.ForgotPassword;
using InfrastructureLoginModel = UnityHub.Infrastructure.CommonModel.LoginModel;
using InfrastructureRegisterModel = UnityHub.Infrastructure.CommonModel.RegisterModel;
using InfrastructureReSentVerificationCode = UnityHub.Infrastructure.CommonModel.ReSentVerificationCode;
using InfrastructureResetPassword = UnityHub.Infrastructure.CommonModel.ResetPassword;
using InfrastructureResponse = UnityHub.Infrastructure.CommonModel.Response;
using InfrastructureUpdateUserProfile = UnityHub.Infrastructure.CommonModel.UpdateUserProfile;

namespace UnityHub.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly IAuthRepository _authRepository;

        public AuthService(IAuthRepository authRepository)
        {
            _authRepository = authRepository ?? throw new ArgumentNullException(nameof(authRepository));
        }


        public async Task<CustomApiResponse<UserBasicDetails>> LoginAsync(LoginModel model)
        {
            var infraModel = ConvertData<LoginModel, InfrastructureLoginModel>(model);
            var response = await _authRepository.Login(infraModel);
            var user = MapToUserBasicDetails(response);
            return ConvertResponse(response, user);
        }

        public async Task<CustomApiResponse<UserBasicDetails>> RegisterAsync(RegisterModel model)
        {
            var infraModel = ConvertData<RegisterModel, InfrastructureRegisterModel>(model);
            var response = await _authRepository.Register(infraModel);
            var user = MapToUserBasicDetails(response);
            return ConvertResponse(response, user);
        }

        public async Task<CustomApiResponse<object>> VerifyTwoFactorCodeAsync(string email, string code)
        {
            var response = await _authRepository.VerifyTwoFactorCodeAsync(email, code);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<object>> ForgotPassword(ForgotPassword email)
        {
            var infraModel = ConvertData<ForgotPassword, InfrastructureForgotPassword>(email);
            var response = await _authRepository.ForgotPassword(infraModel);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<object>> ResetPassword(ResetPassword resetPassword)
        {
            var infraModel = ConvertData<ResetPassword, InfrastructureResetPassword>(resetPassword);
            var response = await _authRepository.ResetPassword(infraModel);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<object>> ChangeUserPassword(ChangeUserPassword changeUserPassword)
        {
            var infraModel = ConvertData<ChangeUserPassword, InfrastructureChangeUserPassword>(changeUserPassword);
            var response = await _authRepository.ChangeUserPassword(infraModel);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<object>> ReSentVerificationCode(ReSentVerificationCode reSentVerification)
        {
            var infraModel = ConvertData<ReSentVerificationCode, InfrastructureReSentVerificationCode>(reSentVerification);
            var response = await _authRepository.ReSentVerificationCode(infraModel);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<object>> UpdateUserProfile(UpdateUserProfile updateUserProfile)
        {
            var infraModel = ConvertData<UpdateUserProfile, InfrastructureUpdateUserProfile>(updateUserProfile);
            var response = await _authRepository.UpdateUserProfile(infraModel);
            return ConvertResponse<object>(response);
        }

        public async Task<CustomApiResponse<UserBasicDetails>> GetUserProfileAsync(string email)
        {
            var response = await _authRepository.GetUserProfileAsync(email);
            var user = MapToUserBasicDetails(response);
            return ConvertResponse(response, user);
        }


        // Generic data converter method for mapping between types
        private TOut ConvertData<TIn, TOut>(TIn input)
            where TOut : new()
        {
            var output = new TOut();
            foreach (var propIn in typeof(TIn).GetProperties())
            {
                var propOut = typeof(TOut).GetProperty(propIn.Name);
                if (propOut != null && propOut.CanWrite)
                {
                    propOut.SetValue(output, propIn.GetValue(input));
                }
            }
            return output;
        }

        // Helper to convert Infrastructure.Response to Core.CustomApiResponse<T>
        private CustomApiResponse<T> ConvertResponse<T>(InfrastructureResponse response, T data = default)
        {
            return new CustomApiResponse<T>
            {
                StatusCode = response.Status == "Success" ? 200 : 400,
                Message = response.Message,
                Data = data,
                Token = response.Token,
                Expiration = response.Expiration
            };
        }

        // Helper to map Infrastructure.Response to UserBasicDetails
        private UserBasicDetails MapToUserBasicDetails(InfrastructureResponse response)
        {
            return new UserBasicDetails
            {
                UserId = response.UserId,
                Username = response.Username,
                FirstName = response.FirstName,
                LastName = response.LastName,
                Email = response.Email,
                PhoneNumber = response.PhoneNumber,
                Location = response.Location,
                ProfileUrl = response.ProfileUrl,
                IsServiceProvider = response.IsServiceProvider ?? false,
                Role = response.Roles != null && response.Roles.Count > 0 ? response.Roles[0] : null
            };
        }
    }
}