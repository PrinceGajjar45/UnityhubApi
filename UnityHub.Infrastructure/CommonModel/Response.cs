using System.Text.Json.Serialization;
using UnityHub.Infrastructure.Data;
using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Infrastructure.CommonModel
{
    public class Response
    {
        // ...existing code...
        public Response WithUserData(ApplicationUser user)
        {
            if (user != null)
            {
                var userDto = new UserDto
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    Location = $"{user.Address}, {user.City}, {user.State}, {user.Country}",
                    ProfileUrl = user.ProfileUrl,
                    IsServiceProvider = user.IsServiceProvider,
                    Address = user.Address,
                    City = user.City,
                    State = user.State,
                    Country = user.Country,
                    ZipCode = user.ZipCode,
                    Latitude = user.Latitude,
                    Longitude = user.Longitude
                };
                Data = userDto;
                UserId = user.Id;
                Username = user.UserName;
                FirstName = user.FirstName;
                LastName = user.LastName;
                Email = user.Email;
                PhoneNumber = user.PhoneNumber;
                Location = $"{user.Address}, {user.City}, {user.State}, {user.Country}";
                ProfileUrl = user.ProfileUrl;
            }
            return this;
        }

        public Response WithData(object data)
        {
            Data = data;
            return this;
        }
        // ...existing code...
    }
    // ...existing code...
}
