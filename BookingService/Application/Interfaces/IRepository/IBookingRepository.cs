using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.IRepository
{
    public interface IBookingRepository
    {
        Task<Booking> AddAsync(Booking booking, CancellationToken ct = default);
        Task<Booking?> GetByIdAsync(Guid id, CancellationToken ct = default);
        Task<List<Booking>> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
        Task<List<Booking>> GetByApartmentIdAsync(Guid apartmentId, CancellationToken ct = default);
        Task<bool> IsApartmentAvailableAsync(Guid apartmentId, DateTime start, DateTime end, CancellationToken ct = default);
        Task UpdateAsync(Booking booking, CancellationToken ct = default);
        Task<List<Booking>> GetAllAsync();
    }
}
