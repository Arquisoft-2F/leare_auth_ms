using IdentityManagerServerApi.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;

namespace auth_ms_api
{
    public class Startup
    {
        public void Configure(IApplicationBuilder app)
        {
            var _db = app.ApplicationServices.CreateScope().ServiceProvider.GetRequiredService<AppDbContext>();
            if (_db != null)
            {
                if (_db.Database.GetPendingMigrations().Any())
                {
                    _db.Database.Migrate();
                }
            }
        }
    }
}
