using System.ComponentModel.DataAnnotations;

namespace UnityHub.Core.Models
{
    public class RegisterModel
    {
        public string Username { get; set; }

        [Required(ErrorMessage = "User FirstName is required")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "User LastName is required")]
        public string LastName { get; set; }

        // Role added to preserve flow from API -> Core -> Infrastructure
        public string Role { get; set; }

        // Replace single Location with detailed address fields
        public string Address { get; set; }

        [Required(ErrorMessage = "City is required")]
        public string City { get; set; }

        [Required(ErrorMessage = "State is required")]
        public string State { get; set; }

        [Required(ErrorMessage = "Country is required")]
        public string Country { get; set; }

        public string ZipCode { get; set; }

        // Optional geographic coordinates
        public decimal? Latitude { get; set; }
        public decimal? Longitude { get; set; }

        public string ProfileUrl { get; set; }

        [Phone(ErrorMessage = "Invalid phone number format")]
        public string PhoneNumber { get; set; }

        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Confirm Password is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; }

        public string Location { get; set; }
    }
}