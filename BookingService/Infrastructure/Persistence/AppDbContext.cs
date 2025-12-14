using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions options) : base(options) { }
        public DbSet<Booking> Bookings => Set<Booking>();
        public DbSet<ApartmentCache> ApartmentCaches => Set<ApartmentCache>();
        public DbSet<UserCache> UserCaches => Set<UserCache>();
    }
}
