using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using UnityHub.API.Authentication;
using UnityHub.Core.CommonModel;
using UnityHub.Core.Interface;

namespace UnityHub.API.Controllers
{
    [Route("api/auth")]
    [ApiController]
    //[Authorize] // Default to requiring authorization
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        private TTarget ConvertData<TSource, TTarget>(TSource source)
            where TSource : class, new()
            where TTarget : class, new()
        {
            if (source == null)
                return null;

            try
            {
                var target = new TTarget();
                var sourceProperties = typeof(TSource).GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var targetProperties = typeof(TTarget).GetProperties(BindingFlags.Public | BindingFlags.Instance);

                foreach (var sourceProp in sourceProperties)
                {
                    // Skip if property doesn't have a getter
                    if (!sourceProp.CanRead)
                        continue;

                    var targetProp = targetProperties.FirstOrDefault(p =>
                        p.Name == sourceProp.Name &&
                        p.PropertyType == sourceProp.PropertyType);

                    if (targetProp != null && targetProp.CanWrite)
                    {
                        try
                        {
                            var value = sourceProp.GetValue(source);
                            targetProp.SetValue(target, value);
                        }
                        catch (Exception)
                        {

                        }
                    }
                }

                return target;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Conversion from {typeof(TSource).Name} to {typeof(TTarget).Name} failed", ex);
            }
        }

        /// <summary>
        /// Authenticates a user and returns a JWT token if successful.
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous] // Allow anonymous access for login
        public async Task<IActionResult> LoginAsync([FromBody] UnityHub.API.Authentication.LoginModel loginRequest)
        {
            var loginModel = ConvertData<UnityHub.API.Authentication.LoginModel, UnityHub.Core.Models.LoginModel>(loginRequest);
            var response = await _authService.LoginAsync(loginModel);
            return StatusCode(response.StatusCode, response);
        }

        /// <summary>
        /// Registers a new user and returns their details with a JWT token.
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous] // Allow anonymous access for registration
        public async Task<IActionResult> RegisterAsync([FromBody] UnityHub.API.Authentication.RegisterModel registerRequest)
        {
            var registerModel = ConvertData<UnityHub.API.Authentication.RegisterModel, UnityHub.Core.Models.RegisterModel>(registerRequest);
            var response = await _authService.RegisterAsync(registerModel);
            return StatusCode(response.StatusCode, response);
        }


        /// <summary>
        /// Updates the profile of the current user.
        /// </summary>
        [HttpPatch("Update-profile")]
        public async Task<IActionResult> UpdateProfileAsync([FromBody] UpdateUserProfile updateRequest)
        {
            try
            {
                var requestModel = ConvertData<UpdateUserProfile, UnityHub.Core.Models.UpdateUserProfile>(updateRequest);
                var response = await _authService.UpdateUserProfile(requestModel);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }


        /// <summary>
        /// Resends the verification code to the user's email address.
        /// </summary>
        [HttpPatch("resend-verification-code")]
        public async Task<IActionResult> ResendVerificationCodeAsync([FromBody] ReSentVerificationCode resendRequest)
        {
            try
            {
                var requestModel = ConvertData<ReSentVerificationCode, UnityHub.Core.Models.ReSentVerificationCode>(resendRequest);
                var response = await _authService.ReSentVerificationCode(requestModel);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }


        /// <summary>
        /// Verifies the two-factor authentication (2FA) code for a user.
        /// </summary>
        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactorAsync([FromBody] TwoFactorRequestModel model)
        {
            try
            {
                var response = await _authService.VerifyTwoFactorCodeAsync(model.PhoneNumber, model.OTP);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }

        /// <summary>
        /// Initiates the forgot password process for a user.
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous] // Allow anonymous access for forgot password
        public async Task<IActionResult> ForgotPasswordAsync([FromBody] ForgotPasswordModel forgotRequest)
        {
            try
            {
                var forgotPassword = ConvertData<ForgotPasswordModel, UnityHub.Core.Models.ForgotPassword>(forgotRequest);
                var response = await _authService.ForgotPassword(forgotPassword);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }

        /// <summary>
        /// Resets the user's password using a reset token.
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous] // Allow anonymous access for password reset
        public async Task<IActionResult> ResetPasswordAsync([FromBody] ResetPasswordModel resetRequest)
        {
            try
            {
                var resetPassword = ConvertData<ResetPasswordModel, UnityHub.Core.Models.ResetPassword>(resetRequest);
                var response = await _authService.ResetPassword(resetPassword);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }


        /// <summary>
        /// Changes the password for an existing user.
        /// </summary>
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangeUserPasswordModel changeRequest)
        {
            try
            {
                var changeUserPassword = ConvertData<ChangeUserPasswordModel, UnityHub.Core.Models.ChangeUserPassword>(changeRequest);
                var response = await _authService.ChangeUserPassword(changeUserPassword);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", ex.Message });
            }
        }


        /// <summary>
        /// Gets the profile of the currently authenticated user.
        /// </summary>
        [HttpGet("Get-profile")]
        public async Task<IActionResult> GetProfileAsync([FromQuery] string phoneNumber)
        {
            try
            {
                if (string.IsNullOrEmpty(phoneNumber))
                {
                    return Unauthorized(new CustomApiResponse<object> { StatusCode = 401, Message = "User is not authenticated." });
                }
                var response = await _authService.GetUserProfileAsync(phoneNumber);
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new CustomApiResponse<object> { StatusCode = 500, Message = ex.Message });
            }
        }


        /// <summary>
        /// Get All User Role For Select Specific Role To Register New Account 
        /// </summary>
        /// <returns></returns>
        [HttpGet("Get-User-Role")]
        [AllowAnonymous] // Allow anonymous access for getting user roles (needed for registration)
        public async Task<IActionResult> GetGetUserRoleAsync()
        {
            try
            {
                var response = await _authService.GetAllRoleNamesAsync();
                return StatusCode(response.StatusCode, response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new CustomApiResponse<object>
                {
                    StatusCode = 500,
                    Message = $"Internal server error: {ex.Message}"
                });
            }
        }

        /// <summary>
        /// Validate postal code and retrieve location information.
        /// </summary>
        [HttpGet]
        [Route("validate-pincode/{pinCode}")]
        public async Task<ActionResult<CustomApiResponse<object>>> ValidatePinCode(string pinCode)
        {
            try
            {
                var result = await _authService.ValidateAndGetLocationByPinCode(pinCode);
                if (result.StatusCode != 200)
                    return BadRequest(result);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Status = "Error", Message = ex.Message });
            }
        }
    }
}