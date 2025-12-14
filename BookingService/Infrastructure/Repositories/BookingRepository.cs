using Application.Interfaces.IRepository;
using Domain.Entities;
using Domain.Enums;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public class BookingRepository : IBookingRepository
    {
        private readonly AppDbContext _db;

        public BookingRepository(AppDbContext db)
        {
            _db = db;
        }

        public async Task<Booking> AddAsync(Booking booking, CancellationToken ct = default)
        {
            _db.Bookings.Add(booking);
            await _db.SaveChangesAsync(ct);
            return booking;
        }

        public Task<List<Booking>> GetAllAsync()
            => _db.Bookings.Include(x => x.Apartment).Include(x => x.User).ToListAsync();

        public async Task<Booking?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => await _db.Bookings.FindAsync(new object[] { id }, ct);

        public async Task<List<Booking>> GetByUserIdAsync(Guid userId, CancellationToken ct = default)
            => await _db.Bookings.Where(b => b.UserId == userId).OrderByDescending(b => b.CreatedAt).ToListAsync(ct);

        public async Task<List<Booking>> GetByApartmentIdAsync(Guid apartmentId, CancellationToken ct = default)
            => await _db.Bookings.Where(b => b.ApartmentId == apartmentId).OrderByDescending(b => b.CreatedAt).ToListAsync(ct);

        public async Task<bool> IsApartmentAvailableAsync(Guid apartmentId, DateTime start, DateTime end, CancellationToken ct = default)
        {
            var conflict = await _db.Bookings.AnyAsync(b =>
                b.ApartmentId == apartmentId &&
                b.Status == BookingStatus.Confirmed &&
                b.CheckIn < end &&
                b.CheckOut > start, ct);
            return !conflict;
        }

        public async Task UpdateAsync(Booking booking, CancellationToken ct = default)
        {
            _db.Bookings.Update(booking);
            await _db.SaveChangesAsync(ct);
        }

    }
}
