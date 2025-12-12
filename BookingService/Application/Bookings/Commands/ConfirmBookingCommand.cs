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
    public class ConfirmBookingCommand : IRequest<bool>
    {
        public Guid Id { get; set; }
        public class ConfirmBookingHandler : IRequestHandler<ConfirmBookingCommand, bool>
        {
            private readonly IBookingRepository _repo;

            public ConfirmBookingHandler(IBookingRepository repo)
            {
                _repo = repo;
            }

            public async Task<bool> Handle(ConfirmBookingCommand request, CancellationToken cancellationToken)
            {
                var booking = await _repo.GetByIdAsync(request.Id);
                if (booking == null)
                    throw new KeyNotFoundException("Booking not found");

                booking.Status = BookingStatus.Confirmed;
                booking.UpdatedAt = DateTime.Now;

                await _repo.UpdateAsync(booking);

                return true;
            }
        }
    }
}
