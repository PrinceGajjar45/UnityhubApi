// AuthMappingProfile.cs
using AutoMapper;
using UnityHub.API.Authentication;
using UnityHub.Core.Models;

namespace UnityHub.API.Mappings
{
    public class AuthMappingProfile : Profile
    {
        public AuthMappingProfile()
        {
            // API -> Service mappings
            CreateMap<Authentication.LoginModel, Core.Models.LoginModel>();
            CreateMap<Authentication.RegisterModel, Core.Models.RegisterModel>();
            CreateMap<Authentication.UpdateUserProfile, Core.Models.UpdateUserProfile>();
            CreateMap<ForgotPasswordModel, ForgotPassword>();
            CreateMap<ResetPasswordModel, ResetPassword>();
            CreateMap<ChangeUserPasswordModel, ChangeUserPassword>();
            CreateMap<Authentication.ReSentVerificationCode, Core.Models.ReSentVerificationCode>();

        }
    }
}