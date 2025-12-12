using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace Infrastructure.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions options) : base(options) { }

    public DbSet<Apartment> Apartments => Set<Apartment>();
    public DbSet<ApartmentImages> ApartmentImages => Set<ApartmentImages>();
}
