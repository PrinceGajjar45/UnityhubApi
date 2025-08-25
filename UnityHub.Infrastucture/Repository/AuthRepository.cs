using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UnityHub.Infrastructure.Data;
using UnityHub.Infrastructure.Interface;
using UnityHub.Infrastructure.Models;

namespace UnityHub.Infrastructure.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;

        public AuthRepository(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        public async Task<Response> Login(LoginModel model)
        {
            try
            {
                if (model == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Login model cannot be null"
                    };
                }
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Invalid email or password"
                    };
                }

                //if (!user.EmailConfirmed)
                //{
                //    return new Response
                //    {
                //        Status = "Error",
                //        Message = "Email not confirmed. Please check your inbox."
                //    };
                //}

                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var jwtSecret = _configuration["JWT:Secret"];
                if (string.IsNullOrEmpty(jwtSecret))
                {
                    throw new ArgumentNullException("JWT Secret is not configured");
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(24),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                return new Response
                {
                    Status = "Success",
                    Message = "Login successful",
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Expiration = token.ValidTo
                };
            }
            catch (SecurityTokenException ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"Token generation failed: {ex.Message}"
                };
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred during login: {ex.Message}"
                };
            }
        }

        public async Task<Response> Register(RegisterModel model)
        {
            try
            {
                if (model == null)
                    return new Response
                    {
                        Status = "Error",
                        Message = "Register model cannot be null"
                    };

                var userExists = await _userManager.FindByEmailAsync(model.Email);
                if (userExists != null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "User already exists!"
                    };
                }

                if (model.Password != model.ConfirmPassword)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Passwords do not match"
                    };
                }

                var user = new ApplicationUser
                {
                    UserName = model.Username,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    PhoneNumber = model.PhoneNumber,
                    IsServiceProvider = model.IsServiceProvider,
                    Location = model.Location,
                    ProfileUrl = model.ProfileUrl,
                    Email = model.Email,
                    EmailConfirmed = false
                };
                try
                {
                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (!result.Succeeded)
                    {
                        return new Response
                        {
                            Status = "Error",
                            Message = string.Join(", ", result.Errors.Select(x => "Code " + x.Code + " Description" + x.Description))
                        };
                    }
                }
                catch (Exception ex)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = $"Failed to Create User: {ex.Message}"
                    };

                }

                // Generate 2FA code
                var twoFactorCode = GenerateSecureRandomCode();
                user.TwoFactorCode = twoFactorCode;
                user.TwoFactorCodeExpiration = DateTime.UtcNow.AddMinutes(10);
                await _userManager.UpdateAsync(user);


                // Send 2FA code via email
                var subject = "Your UnityHub Verification Code";
                var emailMessage = $"Your verification code is: <b>{twoFactorCode}</b>. It will expire in 10 minutes.";
                var senderEmail = _configuration["AppSettings:SenderEmail"];

                if (string.IsNullOrEmpty(senderEmail))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Sender email is not configured."
                    };
                }

                try
                {
                    _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);
                }
                catch (Exception ex)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = $"Failed to send verification email: {ex.Message}"
                    };
                }

                return new Response
                {
                    Status = "Success",
                    Message = "User registered successfully. Please check your email for the verification code."
                };
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
            if (reSentVerification == null)
            {
                return new Response
                {
                    Status = "Error",
                    Message = "Request cannot be null."
                };
            }

            var user = await _userManager.FindByEmailAsync(reSentVerification.Email);
            if (user == null)
            {
                return new Response
                {
                    Status = "Success",
                    Message = "If the email exists, a verification code has been sent."
                };
            }

            var twoFactorCode = GenerateSecureRandomCode();
            user.TwoFactorCode = twoFactorCode;
            user.TwoFactorCodeExpiration = DateTime.UtcNow.AddMinutes(10);

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return new Response
                {
                    Status = "Error",
                    Message = "Failed to update user verification code."
                };
            }

            var subject = "Your UnityHub Verification Code";
            var emailMessage = $"Your verification code is: <b>{twoFactorCode}</b>. It will expire in 10 minutes.";
            var senderEmail = _configuration["AppSettings:SenderEmail"];

            if (string.IsNullOrEmpty(senderEmail))
            {
                return new Response
                {
                    Status = "Error",
                    Message = "Sender email is not configured."
                };
            }

            try
            {
                _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);

                return new Response
                {
                    Status = "Success", // Changed from "Error" to "Success"
                    Message = "Verification code sent successfully."
                };
            }
            catch (Exception)
            {
                // Log the exception for debugging purposes

                return new Response
                {
                    Status = "Error",
                    Message = "Failed to send verification email. Please try again later."
                };
            }
        }

        public async Task<Response> VerifyTwoFactorCodeAsync(string email, string code)
        {
            try
            {
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "User ID and code are required"
                    };
                }

                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "User not found"
                    };
                }

                if (user.TwoFactorCode == null || user.TwoFactorCodeExpiration == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "No verification code found. Please request a new one."
                    };
                }

                if (user.TwoFactorCodeExpiration < DateTime.UtcNow)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Verification code expired. Please request a new one."
                    };
                }

                if (user.TwoFactorCode != code)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Invalid verification code."
                    };
                }

                user.EmailConfirmed = true;
                user.TwoFactorEnabled = true;
                user.TwoFactorCode = null;
                user.TwoFactorCodeExpiration = null;

                var updateResult = await _userManager.UpdateAsync(user);
                if (!updateResult.Succeeded)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = string.Join(", ", updateResult.Errors.Select(e => e.Description))
                    };
                }

                return new Response
                {
                    Status = "Success",
                    Message = "Email confirmed successfully."
                };
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred while verifying 2FA code: {ex.Message}"
                };
            }
        }

        public async Task<Response> ForgotPassword(ForgotPassword email)
        {
            try
            {
                if (email == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Request cannot be null"
                    };
                }

                if (string.IsNullOrWhiteSpace(email.Email))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Email is required"
                    };
                }

                var user = await _userManager.FindByEmailAsync(email.Email);
                if (user == null)
                {
                    // For security reasons, don't reveal that the user doesn't exist
                    return new Response
                    {
                        Status = "Success",
                        Message = "If the email exists, a password reset link has been sent"
                    };
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
                var resetLink = $"{_configuration["AppSettings:FrontendUrl"]}/reset-password?token={encodedToken}&email={WebUtility.UrlEncode(user.Email)}";

                var subject = "Your UnityHub Password Reset";
                var emailMessage = $@"
            <h3>Password Reset Request</h3>
            <p>You requested to reset your password. Click the link below to proceed:</p>
            <p><a href='{resetLink}'>Reset Password</a></p>
            <p>This link will expire in 2 hours.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <br>
            <p><small>Or copy this link: {resetLink}</small></p>";

                var senderEmail = _configuration["AppSettings:SenderEmail"];

                try
                {
                    _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);

                    return new Response
                    {
                        Status = "Success",
                        Message = "Password reset email sent successfully"
                    };
                }
                catch (Exception)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Failed to send password reset email. Please try again later."
                    };
                }
            }
            catch (Exception)
            {
                return new Response
                {
                    Status = "Error",
                    Message = "An unexpected error occurred. Please try again later."
                };
            }
        }

        public async Task<Response> ResetPassword(ResetPassword resetPassword)
        {
            try
            {
                if (resetPassword == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Request cannot be null"
                    };
                }

                if (string.IsNullOrWhiteSpace(resetPassword.Email))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Email is required"
                    };
                }

                if (string.IsNullOrWhiteSpace(resetPassword.Token))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Token is required"
                    };
                }

                if (string.IsNullOrWhiteSpace(resetPassword.ConfirmPassword))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Password is required"
                    };
                }

                var user = await _userManager.FindByEmailAsync(resetPassword.Email);
                if (user == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Invalid reset request"
                    };
                }

                // Decode the token
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetPassword.Token));

                var resetPassResult = await _userManager.ResetPasswordAsync(user, decodedToken, resetPassword.ConfirmPassword);

                if (!resetPassResult.Succeeded)
                {
                    var errors = string.Join(", ", resetPassResult.Errors.Select(e => e.Description));
                    return new Response
                    {
                        Status = "Error",
                        Message = $"Password reset failed: {errors}"
                    };
                }

                return new Response
                {
                    Status = "Success",
                    Message = "Password reset successfully"
                };
            }
            catch (Exception)
            {
                return new Response
                {
                    Status = "Error",
                    Message = "An error occurred while resetting password. Please try again later."
                };
            }
        }

        public async Task<Response> ChangeUserPassword(ChangeUserPassword changeUserPassword)
        {
            try
            {

                if (string.IsNullOrWhiteSpace(changeUserPassword.Email))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Email is required"
                    };
                }
                if (string.IsNullOrWhiteSpace(changeUserPassword.OldPassword))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Old Password is required"
                    };
                }
                if (string.IsNullOrWhiteSpace(changeUserPassword.NewPassword))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "New Password is required"
                    };
                }
                if (string.IsNullOrWhiteSpace(changeUserPassword.ConfirmNewPassword))
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "Confirm New Password is required"
                    };
                }

                var user = await _userManager.FindByEmailAsync(changeUserPassword.Email);
                if (user == null)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "User not found"
                    };
                }

                if (changeUserPassword.NewPassword != changeUserPassword.ConfirmNewPassword)
                {
                    return new Response
                    {
                        Status = "Error",
                        Message = "New password and confirm password do not match"
                    };
                }

                var result = await _userManager.ChangePasswordAsync(user, changeUserPassword.OldPassword, changeUserPassword.NewPassword);
                if (result.Succeeded)
                {
                    return new Response
                    {
                        Status = "Success",
                        Message = "Password changed successfully"
                    };
                }

                return new Response
                {
                    Status = "Error",
                    Message = "Change password functionality is not implemented yet"
                };
            }
            catch (Exception ex)
            {
                return new Response
                {
                    Status = "Error",
                    Message = $"An error occurred while changing password: {ex.Message}"
                };
            }
        }

        private string GenerateSecureRandomCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var tokenBuffer = new byte[4];
            rng.GetBytes(tokenBuffer);

            // Convert to a 6-digit number
            var numericToken = Math.Abs(BitConverter.ToInt32(tokenBuffer, 0)) % 1000000;
            return numericToken.ToString("D6");
        }
    }
}