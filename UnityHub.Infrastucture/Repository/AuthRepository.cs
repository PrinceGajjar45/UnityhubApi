using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UnityHub.Infrastructure.CommonModel;
using UnityHub.Infrastructure.Data;
using UnityHub.Infrastructure.Interface;
using UserRoles = UnityHub.Infrastructure.Data.UserRoles;

namespace UnityHub.Infrastructure.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> _userManager;
        private readonly Microsoft.AspNetCore.Identity.RoleManager<Microsoft.AspNetCore.Identity.IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender<ApplicationUser> _emailSender;

        public AuthRepository(
            Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> userManager,
            Microsoft.AspNetCore.Identity.RoleManager<Microsoft.AspNetCore.Identity.IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailSender<ApplicationUser> emailSender)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
        }

        public async Task<Response> Login(LoginModel model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
                return Response.Error("Email and password are required");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Response.Error("Invalid email or password");

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!isPasswordValid)
                return Response.Error("Invalid email or password");

            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("UserId", user.Id),
                new Claim("FirstName", user.FirstName ?? string.Empty),
                new Claim("LastName", user.LastName ?? string.Empty),
                new Claim("UserRole", userRoles.ToString())
            };
            foreach (var role in userRoles)
                authClaims.Add(new Claim(ClaimTypes.Role, role));

            var jwtSecret = _configuration["JWT:Secret"];
            var validIssuer = _configuration["JWT:ValidIssuer"];
            var validAudience = _configuration["JWT:ValidAudience"];
            if (string.IsNullOrEmpty(jwtSecret) || string.IsNullOrEmpty(validIssuer) || string.IsNullOrEmpty(validAudience))
                return Response.Error("JWT configuration is missing");

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var token = new JwtSecurityToken(
                issuer: validIssuer,
                audience: validAudience,
                expires: DateTime.Now.AddHours(24),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            var tokenExpiry = token.ValidTo;

            return Response.Success("Login successful")
                .WithToken(tokenString, tokenExpiry)
                .WithUserData(user)
                .WithRoles(userRoles.ToList());
        }

        public async Task<Response> Register(RegisterModel model)
        {
            try
            {
                // Validate input parameters
                if (model == null)
                    return Response.Error("Registration model is required");

                if (string.IsNullOrWhiteSpace(model.Email))
                    return Response.Error("Email is required");

                if (string.IsNullOrWhiteSpace(model.Password))
                    return Response.Error("Password is required");

                if (model.Password != model.ConfirmPassword)
                    return Response.Error("Passwords do not match");

                // Check if user already exists
                var userExists = await _userManager.FindByEmailAsync(model.Email.Trim());
                if (userExists != null)
                    return Response.Error("Email is already registered!");

                // Check if phone number already exists
                if (!string.IsNullOrWhiteSpace(model.PhoneNumber))
                {
                    var phoneExists = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == model.PhoneNumber.Trim());
                    if (phoneExists != null)
                        return Response.Error("Phone number is already registered!");
                }

                // Determine user role
                string userRole = !string.IsNullOrWhiteSpace(model.Role)
                    ? model.Role
                    : model.IsServiceProvider ? UserRoles.ServiceProvider : UserRoles.User;

                var validRoles = new[] { UserRoles.Admin, UserRoles.User, UserRoles.ServiceProvider };
                if (!validRoles.Contains(userRole))
                    return Response.Error($"Invalid role specified. Valid roles are: {string.Join(", ", validRoles)}");

                // Get role ID (this was problematic in original code)
                var role = await _roleManager.FindByNameAsync(userRole);
                if (role == null)
                    return Response.Error($"Role '{userRole}' not found in the system");

                var userRoleID = role.Id;

                // Create user object
                var user = new ApplicationUser
                {
                    UserName = model.Username?.Trim() ?? string.Empty,
                    UserRole = userRoleID,
                    Email = model.Email?.Trim() ?? string.Empty,
                    FirstName = model.FirstName?.Trim() ?? string.Empty,
                    LastName = model.LastName?.Trim() ?? string.Empty,
                    PhoneNumber = model.PhoneNumber?.Trim(),
                    ProfileUrl = model.ProfileUrl?.Trim(),
                    Address = model.Address?.Trim(),
                    City = model.City?.Trim(),
                    State = model.State?.Trim(),
                    Country = model.Country?.Trim(),
                    ZipCode = model.ZipCode?.Trim(),
                    Latitude = model.Latitude,
                    Longitude = model.Longitude
                };

                // Create user
                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                    return Response.Error($"User creation failed: {string.Join(", ", result.Errors.Select(x => x.Description))}");

                try
                {
                    // Add user to role
                    var roleResult = await _userManager.AddToRoleAsync(user, userRole);
                    if (!roleResult.Succeeded)
                    {
                        await _userManager.DeleteAsync(user);
                        return Response.Error($"Role assignment failed: {string.Join(", ", roleResult.Errors.Select(x => x.Description))}");
                    }

                    // Generate and store two-factor code
                    var twoFactorCode = GenerateSecureRandomCode();
                    user.TwoFactorCode = twoFactorCode;
                    user.TwoFactorCodeExpiration = DateTime.UtcNow.AddMinutes(10);
                    var updateResult = await _userManager.UpdateAsync(user);

                    if (!updateResult.Succeeded)
                    {
                        // Log this error but continue since it's not critical
                    }

                    // Send verification email (fire and forget)
                    var senderEmail = _configuration?["AppSettings:SenderEmail"];
                    if (!string.IsNullOrWhiteSpace(senderEmail) && !string.IsNullOrWhiteSpace(user.Email))
                    {
                        try
                        {
                            var subject = "Your UnityHub Verification Code";
                            var emailMessage = $"Your verification code is: <b>{user.TwoFactorCode}</b>. It will expire in 10 minutes.";
                            _ = _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);
                        }
                        catch (Exception)
                        {
                            // Log email sending error but continue registration
                            // You might want to add logging here: _logger.LogError(emailEx, "Failed to send verification email");
                        }
                    }

                    // Generate JWT token
                    var jwtSecret = _configuration?["JWT:Secret"];
                    if (string.IsNullOrWhiteSpace(jwtSecret))
                        return Response.Error("JWT configuration is missing");

                    var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("UserId", user.Id),
                new Claim("FirstName", user.FirstName ?? string.Empty),
                new Claim("LastName", user.LastName ?? string.Empty),
                new Claim(ClaimTypes.Role, userRole)
            };

                    var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
                    var token = new JwtSecurityToken(
                        issuer: _configuration?["JWT:ValidIssuer"],
                        audience: _configuration?["JWT:ValidAudience"],
                        expires: DateTime.Now.AddHours(24),
                        claims: authClaims,
                        signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    var tokenExpiry = token.ValidTo;

                    return Response.Success($"User registered successfully as {userRole}.")
                        .WithToken(tokenString, tokenExpiry)
                        .WithUserData(user)
                        .WithRoles(new List<string> { userRole });
                }
                catch (Exception innerEx)
                {
                    // If anything fails after user creation, attempt to clean up
                    try
                    {
                        await _userManager.DeleteAsync(user);
                    }
                    catch
                    {
                        // Suppress cleanup errors
                    }

                    return Response.Error($"Registration failed: {innerEx.Message}");
                }
            }
            catch (Exception)
            {
                return Response.Error("An unexpected error occurred during registration. Please try again.");
            }
        }

        public async Task<Response> VerifyTwoFactorCodeAsync(string email, string code)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
                return Response.Error("Email and code are required");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return Response.NotFound("User");
            if (user.TwoFactorCode == null || user.TwoFactorCodeExpiration == null)
                return Response.Error("No verification code found");
            if (user.TwoFactorCodeExpiration < DateTime.UtcNow)
                return Response.Error("Verification code expired");
            if (user.TwoFactorCode != code)
                return Response.Error("Invalid verification code");
            user.EmailConfirmed = true;
            user.TwoFactorEnabled = true;
            user.TwoFactorCode = null;
            user.TwoFactorCodeExpiration = null;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return Response.Error($"Verification failed: {string.Join(", ", updateResult.Errors.Select(e => e.Description))}");
            return Response.Success("2FA verified");
        }

        public async Task<Response> ForgotPassword(ForgotPassword email)
        {
            if (email == null || string.IsNullOrEmpty(email.Email))
                return Response.Error("Email is required");
            var user = await _userManager.FindByEmailAsync(email.Email);
            if (user == null)
                return Response.Success("If the email exists, a password reset link has been sent");
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = $"{_configuration["AppSettings:FrontendUrl"]}/reset-password?token={encodedToken}&email={WebUtility.UrlEncode(user.Email)}";
            var subject = "Your UnityHub Password Reset";
            var emailMessage = $@"<h3>Password Reset Request</h3><p>You requested to reset your password. Click the link below to proceed:</p><p><a href='{resetLink}'>Reset Password</a></p><p>This link will expire in 2 hours.</p>";
            var senderEmail = _configuration["AppSettings:SenderEmail"];
            _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);
            return Response.Success("Forgot password email sent");
        }

        public async Task<Response> ResetPassword(ResetPassword resetPassword)
        {
            if (resetPassword == null || string.IsNullOrEmpty(resetPassword.Email) || string.IsNullOrEmpty(resetPassword.Token) || string.IsNullOrEmpty(resetPassword.Password))
                return Response.Error("All fields are required");
            if (resetPassword.Password != resetPassword.ConfirmPassword)
                return Response.Error("Passwords do not match");
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user == null)
                return Response.Error("Invalid reset request");
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetPassword.Token));
            var resetPassResult = await _userManager.ResetPasswordAsync(user, decodedToken, resetPassword.Password);
            if (!resetPassResult.Succeeded)
                return Response.Error($"Password reset failed: {string.Join(", ", resetPassResult.Errors.Select(e => e.Description))}");
            return Response.Success("Password reset");
        }

        public async Task<Response> ChangeUserPassword(ChangeUserPassword changeUserPassword)
        {
            if (changeUserPassword == null || string.IsNullOrEmpty(changeUserPassword.Email) || string.IsNullOrEmpty(changeUserPassword.OldPassword) || string.IsNullOrEmpty(changeUserPassword.NewPassword))
                return Response.Error("All fields are required");
            if (changeUserPassword.NewPassword != changeUserPassword.ConfirmNewPassword)
                return Response.Error("New password and confirm password do not match");
            var user = await _userManager.FindByEmailAsync(changeUserPassword.Email);
            if (user == null)
                return Response.NotFound("User");
            var result = await _userManager.ChangePasswordAsync(user, changeUserPassword.OldPassword, changeUserPassword.NewPassword);
            if (!result.Succeeded)
                return Response.Error($"Password change failed: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            return Response.Success("Password changed");
        }

        public async Task<Response> ReSentVerificationCode(ReSentVerificationCode reSentVerification)
        {
            if (reSentVerification == null || string.IsNullOrEmpty(reSentVerification.Email))
                return Response.Error("Email is required");
            var user = await _userManager.FindByEmailAsync(reSentVerification.Email);
            if (user == null)
                return Response.Success("If the email exists, a verification code has been sent");
            var twoFactorCode = GenerateSecureRandomCode();
            user.TwoFactorCode = twoFactorCode;
            user.TwoFactorCodeExpiration = DateTime.UtcNow.AddMinutes(10);
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return Response.Error("Failed to update verification code");
            var subject = "Your UnityHub Verification Code";
            var emailMessage = $"Your verification code is: <b>{twoFactorCode}</b>. It will expire in 10 minutes.";
            var senderEmail = _configuration["AppSettings:SenderEmail"];
            _emailSender.SendEmailAsync(senderEmail, user.Email, subject, emailMessage);
            return Response.Success("Verification code resent");
        }

        public async Task<Response> UpdateUserProfile(UpdateUserProfile updateUserProfile)
        {
            if (updateUserProfile == null || string.IsNullOrEmpty(updateUserProfile.Email))
                return Response.Error("Email is required");
            var user = await _userManager.FindByEmailAsync(updateUserProfile.Email);
            if (user == null)
                return Response.NotFound("User");
            if (!string.IsNullOrEmpty(updateUserProfile.FirstName))
                user.FirstName = updateUserProfile.FirstName;
            if (!string.IsNullOrEmpty(updateUserProfile.LastName))
                user.LastName = updateUserProfile.LastName;
            if (!string.IsNullOrEmpty(updateUserProfile.PhoneNumber))
                user.PhoneNumber = updateUserProfile.PhoneNumber;
            if (!string.IsNullOrEmpty(updateUserProfile.ProfileUrl))
                user.ProfileUrl = updateUserProfile.ProfileUrl;
            if (!string.IsNullOrEmpty(updateUserProfile.UserName))
                user.UserName = updateUserProfile.UserName;
            UpdateAddressProperties(user, updateUserProfile);
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return Response.Error($"Profile update failed: {string.Join(", ", result.Errors.Select(x => x.Description))}");
            return Response.Success("Profile updated");
        }

        public async Task<Response> GetUserProfileAsync(string email)
        {
            if (string.IsNullOrEmpty(email))
                return Response.Error("Email is required");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return Response.NotFound("User");
            return Response.Success("Profile fetched").WithUserData(user);
        }

        public async Task<Response> GetAllRoleNamesAsync()
        {
            try
            {
                var userRoles = await _roleManager.Roles.ToListAsync();

                if (userRoles == null || !userRoles.Any())
                {
                    return Response.Error("No roles found");
                }

                // Extract role names and filter out null/empty names
                var roleNames = userRoles.Select(r => r.Name)
                                        .Where(name => !string.IsNullOrEmpty(name))
                                        .ToList();

                if (!roleNames.Any())
                {
                    return Response.Error("No valid role names found");
                }

                // Return with roles in the Data property
                return Response.Success("Roles retrieved successfully")
                             .WithRoles(roleNames);
            }
            catch (Exception ex)
            {
                return Response.Error($"Error while getting all roles: {ex.Message}");
            }
        }

        private void UpdateAddressProperties(ApplicationUser user, object updateUserProfile)
        {
            if (updateUserProfile == null) return;
            Type t = updateUserProfile.GetType();
            string? ReadString(string name)
            {
                var p = t.GetProperty(name);
                if (p == null) return null;
                var val = p.GetValue(updateUserProfile);
                return val?.ToString();
            }
            decimal? ReadDecimal(string name)
            {
                var p = t.GetProperty(name);
                if (p == null) return null;
                var val = p.GetValue(updateUserProfile);
                if (val == null) return null;
                if (val is decimal d) return d;
                if (decimal.TryParse(val.ToString(), out var parsed)) return parsed;
                return null;
            }
            var addr = ReadString("Address");
            if (!string.IsNullOrEmpty(addr)) user.Address = addr;
            var city = ReadString("City");
            if (!string.IsNullOrEmpty(city)) user.City = city;
            var state = ReadString("State");
            if (!string.IsNullOrEmpty(state)) user.State = state;
            var country = ReadString("Country");
            if (!string.IsNullOrEmpty(country)) user.Country = country;
            var zip = ReadString("ZipCode");
            if (!string.IsNullOrEmpty(zip)) user.ZipCode = zip;
            var lat = ReadDecimal("Latitude");
            if (lat.HasValue) user.Latitude = lat;
            var lng = ReadDecimal("Longitude");
            if (lng.HasValue) user.Longitude = lng;
            var location = ReadString("Location");
            if (!string.IsNullOrEmpty(location) && string.IsNullOrEmpty(city) && string.IsNullOrEmpty(state) && string.IsNullOrEmpty(country))
            {
                ParseLocationString(location, user);
            }
        }

        private void ParseLocationString(string location, ApplicationUser user)
        {
            if (string.IsNullOrEmpty(location) || user == null) return;
            var parts = location.Split(',');
            if (parts.Length > 0) user.City = parts[0].Trim();
            if (parts.Length > 1) user.State = parts[1].Trim();
            if (parts.Length > 2) user.Country = parts[2].Trim();
        }

        private string GenerateSecureRandomCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var tokenBuffer = new byte[4];
            rng.GetBytes(tokenBuffer);
            var numericToken = Math.Abs(BitConverter.ToInt32(tokenBuffer, 0)) % 1000000;
            return numericToken.ToString("D6");
        }
    }
}