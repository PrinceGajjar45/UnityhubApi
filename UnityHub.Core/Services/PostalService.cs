using System.Text.Json;
using UnityHub.Core.Models;
using UnityHub.Infrastructure.CommonModel;

namespace UnityHub.Core.Services
{
    public class PostalService
    {
        private readonly HttpClient _httpClient;
        private const string BASE_URL = "https://api.postalpincode.in/pincode/";

        public PostalService()
        {
            _httpClient = new HttpClient();
        }

        public async Task<Response> GetLocationDetailsByPinCode(string pinCode)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(pinCode) || !IsValidPinCode(pinCode))
                {
                    return Response.Error("Invalid PIN code format");
                }

                var response = await _httpClient.GetAsync($"{BASE_URL}{pinCode}");
                var content = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    return Response.Error("Failed to fetch location details");
                }

                var postalResponses = JsonSerializer.Deserialize<List<PostalPinCodeResponse>>(content);
                var postalResponse = postalResponses?.FirstOrDefault();

                if (postalResponse == null || postalResponse.Status == "Error" || postalResponse.PostOffice == null || !postalResponse.PostOffice.Any())
                {
                    return Response.Error("Invalid PIN code or no location found");
                }

                var postOffice = postalResponse.PostOffice.First();
                var locationDetails = new
                {
                    Area = postOffice.Name,
                    City = postOffice.District,
                    State = postOffice.State,
                    Country = postOffice.Country,
                    ZipCode = pinCode,
                    District = postOffice.District
                };

                var resp = Response.Success(postalResponse.Message);
                resp.Data = locationDetails;
                return resp;
            }
            catch (Exception ex)
            {
                return Response.Error($"Error fetching location details: {ex.Message}");
            }
        }

        private bool IsValidPinCode(string pinCode)
        {
            return pinCode.Length == 6 && pinCode.All(char.IsDigit);
        }
    }
}