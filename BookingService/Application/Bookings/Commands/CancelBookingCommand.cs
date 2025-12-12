using Application.Interfaces.IRepository;
using Domain.Enums;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Bookings.Commands
{
    public class CancelBookingCommand : IRequest<bool>
    {
        public Guid Id { get; set; }
        public string? CancelReason { get; set; }
        public class CancelBookingHandler : IRequestHandler<CancelBookingCommand, bool>
        {
            private readonly IBookingRepository _repo;

            public CancelBookingHandler(IBookingRepository repo)
            {
                _repo = repo;
            }

            public async Task<bool> Handle(CancelBookingCommand request, CancellationToken cancellationToken)
            {
                var booking = await _repo.GetByIdAsync(request.Id);
                if (booking == null)
                    throw new KeyNotFoundException("Booking not found");

                booking.Status = BookingStatus.Cancelled;
                booking.CancelReason = request.CancelReason?.Trim();
                booking.UpdatedAt = DateTime.Now;

                await _repo.UpdateAsync(booking);

                return true;
            }
        }
    }
}
