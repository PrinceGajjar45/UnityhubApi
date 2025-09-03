using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace UnityHub.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
                : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure decimal precision for Latitude and Longitude
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(u => u.Latitude)
                    .HasPrecision(18, 15); // 18 total digits, 15 decimal places

                entity.Property(u => u.Longitude)
                    .HasPrecision(18, 15); // 18 total digits, 15 decimal places
            });
        }
    }
}