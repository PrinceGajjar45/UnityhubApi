using UnityHub.Core.Interface;
using UnityHub.Core.Models;
using UnityHub.Core.ServiceModel;
using UnityHub.Infrastructure.Interface;

namespace UnityHub.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly IAuthRepository _authRepository;

        public AuthService(IAuthRepository authRepository)
        {
            _authRepository = authRepository;
        }

        public async Task<Response> LoginAsync(LoginModel model)
        {
            try
            {
                var loginModel = new UnityHub.Infrastructure.Models.LoginModel
                {
                    Email = model.Email,
                    Password = model.Password
                };
                var loginResponse = await _authRepository.Login(loginModel);
                var response = new Response
                {
                    Status = loginResponse.Status,
                    Message = loginResponse.Message,
                    Token = loginResponse.Token,
                    Expiration = loginResponse.Expiration
                };
                return response;
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred during Login: {ex.Message}"
                };
            }
        }

        public async Task<Response> RegisterAsync(RegisterModel model)
        {
            try
            {
                var registerModel = new UnityHub.Infrastructure.Models.RegisterModel
                {
                    Username = model.Username,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    PhoneNumber = model.PhoneNumber,
                    IsServiceProvider = model.IsServiceProvider,
                    Location = model.Location,
                    ProfileUrl = model.ProfileUrl,
                    Email = model.Email,
                    Password = model.Password,
                    ConfirmPassword = model.ConfirmPassword

                };
                var response = await _authRepository.Register(registerModel);
                var data = new Response
                {
                    Status = response.Status,
                    Message = response.Message,
                    Token = response.Token,
                    Expiration = response.Expiration
                };
                return data;
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred during registration: {ex.Message}"
                };
            }
        }

        public async Task<Response> ReSentVerificationCode(ReSentVerificationCode reSentVerification)
        {
            try
            {
                var requestModel = new UnityHub.Infrastructure.Models.ReSentVerificationCode
                {
                    Email = reSentVerification.Email
                };
                var response = await _authRepository.ReSentVerificationCode(requestModel);
                var data = new Response
                {
                    Status = response.Status,
                    Message = response.Message,
                    Token = response.Token,
                    Expiration = response.Expiration
                };
                return data;
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred during resent code: {ex.Message}"
                };
            }
        }

        public async Task<Response> VerifyTwoFactorCodeAsync(string email, string code)
        {
            try
            {
                var verifyTwoFactorCode = await _authRepository.VerifyTwoFactorCodeAsync(email, code);
                var response = new Response
                {
                    Status = verifyTwoFactorCode.Status,
                    Message = verifyTwoFactorCode.Message,
                    Token = verifyTwoFactorCode.Token,
                    Expiration = verifyTwoFactorCode.Expiration
                };
                return response;
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred during two-factor verification: {ex.Message}"
                };
            }
        }

        public async Task<Response> ForgotPassword(ForgotPassword email)
        {
            try
            {
                var forgotPasswordModel = new UnityHub.Infrastructure.Models.ForgotPassword
                {
                    Email = email.Email,
                };

                var result = await _authRepository.ForgotPassword(forgotPasswordModel);

                return new Response
                {
                    Status = result.Status,
                    Message = result.Message
                };
            }
            catch (Exception)
            {

                return new Response
                {
                    Status = "Error",
                    Message = "An error occurred while processing your request. Please try again later."
                };
            }
        }

        public async Task<Response> ResetPassword(ResetPassword resetPassword)
        {
            try
            {
                var resetPasswordModel = new UnityHub.Infrastructure.Models.ResetPassword
                {
                    Password = resetPassword.Password,
                    ConfirmPassword = resetPassword.ConfirmPassword,
                    Token = resetPassword.Token,
                    Email = resetPassword.Email
                };

                var response = await _authRepository.ResetPassword(resetPasswordModel);
                return new Response
                {
                    Status = response.Status,
                    Message = response.Message
                };
            }
            catch (Exception)
            {
                return new Response
                {
                    Status = "Error",
                    Message = "An error occurred while processing your request. Please try again later."
                };
            }
        }

        public async Task<Response> ChangeUserPassword(ChangeUserPassword changeUserPassword)
        {
            try
            {
                var changePasswordModel = new UnityHub.Infrastructure.Models.ChangeUserPassword
                {
                    OldPassword = changeUserPassword.OldPassword,
                    NewPassword = changeUserPassword.NewPassword,
                    ConfirmNewPassword = changeUserPassword.ConfirmNewPassword,
                    Email = changeUserPassword.Email
                };
                var response = await _authRepository.ChangeUserPassword(changePasswordModel);
                return new Response
                {
                    Status = response.Status,
                    Message = response.Message
                };
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred while changing the password: {ex.Message}"
                };
            }
        }

    }
}