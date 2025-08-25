using Microsoft.AspNetCore.Mvc;
using UnityHub.API.Authentication;
using UnityHub.Core.Interface;

namespace UnityHub.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthenticateController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UnityHub.API.Authentication.LoginModel model)
        {
            try
            {
                var loginModel = new UnityHub.Core.Models.LoginModel
                {
                    Email = model.Email,
                    Password = model.Password
                };
                var response = await _authService.LoginAsync(loginModel);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    Message = ex.Message
                });
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UnityHub.API.Authentication.RegisterModel model)
        {
            try
            {
                var registerModel = new UnityHub.Core.Models.RegisterModel
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
                var response = await _authService.RegisterAsync(registerModel);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }

        [HttpPatch("ReSent-Verification-Code")]
        public async Task<IActionResult> ReSentVerificationCode([FromBody] ReSentVerificationCode reSentVerification)
        {
            try
            {
                var requestModel = new UnityHub.Core.Models.ReSentVerificationCode
                {
                    Email = reSentVerification.Email
                };
                var response = await _authService.ReSentVerificationCode(requestModel);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorRequestModel model)
        {
            try
            {
                var response = await _authService.VerifyTwoFactorCodeAsync(model.Email, model.OTP);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {
            try
            {
                var resetPassword = new UnityHub.Core.Models.ResetPassword
                {
                    Token = resetPasswordModel.Token,
                    Email = resetPasswordModel.Email,
                    Password = resetPasswordModel.Password,
                    ConfirmPassword = resetPasswordModel.ConfirmPassword
                };
                var response = await _authService.ResetPassword(resetPassword);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }

        [HttpPost("Forgot-Password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel forgotPasswordModel)
        {
            try
            {
                var forgotPassword = new UnityHub.Core.Models.ForgotPassword
                {
                    Email = forgotPasswordModel.Email
                };

                var response = await _authService.ForgotPassword(forgotPassword);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }

        [HttpPost("Change-User-Password")]
        public async Task<IActionResult> ChangeUserPassword([FromBody] ChangeUserPasswordModel changeUserPasswordModel)
        {
            try
            {
                var changeUserPassword = new UnityHub.Core.Models.ChangeUserPassword
                {
                    OldPassword = changeUserPasswordModel.OldPassword,
                    NewPassword = changeUserPasswordModel.NewPassword,
                    ConfirmNewPassword = changeUserPasswordModel.ConfirmNewPassword,
                    Email = changeUserPasswordModel.Email
                };
                var response = await _authService.ChangeUserPassword(changeUserPassword);
                if (response.Status == "Success")
                {
                    return Ok(response);
                }
                return BadRequest(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Status = "Error",
                    ex.Message
                });
            }
        }
    }
}