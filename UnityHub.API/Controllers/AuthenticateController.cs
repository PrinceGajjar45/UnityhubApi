using Microsoft.AspNetCore.Mvc;
using UnityHub.Core.Interface;
using UnityHub.API.Authentication;

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
            catch ( Exception ex)
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