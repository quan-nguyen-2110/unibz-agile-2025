using Application.Interfaces.IRepository;
using Domain.Entities;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public class ApartmentCacheRepository : IApartmentCacheRepository
    {
        private readonly AppDbContext _db;

        public ApartmentCacheRepository(AppDbContext db)
        {
            _db = db;
        }
        public async Task<ApartmentCache> AddAsync(ApartmentCache apartment, CancellationToken ct = default)
        {
            _db.ApartmentCaches.Add(apartment);
            await _db.SaveChangesAsync(ct);
            return apartment;
        }

        public async Task<int> UpdateAsync(ApartmentCache apartment, CancellationToken ct = default)
        {
            _db.ApartmentCaches.Update(apartment);
            return await _db.SaveChangesAsync(ct);
        }

        public async Task<bool> IsExistingAsync(Guid id, CancellationToken ct = default)
            => await _db.ApartmentCaches.AnyAsync(x => x.Id == id);
    }
}
