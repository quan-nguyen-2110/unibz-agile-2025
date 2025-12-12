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
    public class ApartmentImageRepository : IApartmentImageRepository
    {
        private readonly AppDbContext _db;

        public ApartmentImageRepository(AppDbContext db)
        {
            _db = db;
        }

        public async Task AddRangeAsync(IEnumerable<ApartmentImages> images)
        {
            _db.ApartmentImages.AddRange(images);
            await _db.SaveChangesAsync();
        }

        public async Task RemoveRangeAsync(IEnumerable<ApartmentImages> images)
        {
            _db.ApartmentImages.RemoveRange(images);
            await _db.SaveChangesAsync();
        }

        public async Task<List<ApartmentImages>> GetByApartmentIdAsync(Guid apartmentId)
        {
            return await _db.ApartmentImages
                .Where(img => img.ApartmentId == apartmentId)
                .ToListAsync();
        }

        public async Task<List<string>> GetBase64ImagesByApartmentIdAsync(Guid apartmentId)
        {
            return await _db.ApartmentImages
                .Where(img => img.ApartmentId == apartmentId)
                .Select(img => img.Base64Image)
                .ToListAsync();
        }
    }
}
