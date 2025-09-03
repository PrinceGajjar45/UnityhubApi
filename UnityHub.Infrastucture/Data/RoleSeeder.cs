using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace UnityHub.Infrastructure.Data
{
    public class RoleSeeder
    {
        public static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            const int maxRetries = 3;
            var retryDelay = TimeSpan.FromSeconds(2);

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    // Check if database is available
                    var dbContext = roleManager.GetType().GetProperty("Context")?
                        .GetValue(roleManager) as DbContext;

                    if (dbContext != null && !await dbContext.Database.CanConnectAsync())
                    {
                        throw new Exception("Database not available");
                    }

                    // Seed roles
                    if (!await roleManager.RoleExistsAsync("Admin"))
                    {
                        await roleManager.CreateAsync(new IdentityRole("Admin"));
                    }

                    if (!await roleManager.RoleExistsAsync("User"))
                    {
                        await roleManager.CreateAsync(new IdentityRole("User"));
                    }

                    if (!await roleManager.RoleExistsAsync("ServiceProvider"))
                    {
                        await roleManager.CreateAsync(new IdentityRole("ServiceProvider"));
                    }

                    break; // Success, break out of retry loop
                }
                catch (Exception) when (attempt < maxRetries)
                {
                    await Task.Delay(retryDelay * attempt);
                    // Log retry attempt if needed
                }
                catch (Exception ex)
                {
                    // Log final failure
                    Console.WriteLine($"Role seeding failed after {maxRetries} attempts: {ex.Message}");
                    break;
                }
            }
        }
    }
}