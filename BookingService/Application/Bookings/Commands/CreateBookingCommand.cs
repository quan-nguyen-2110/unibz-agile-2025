using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Bookings.Commands
{
    public class CreateBookingCommand : IRequest<Guid>
    {
        public Guid ApartmentId { get; set; }
        public Guid UserId { get; set; }
        public DateTime CheckIn { get; set; }
        public DateTime CheckOut { get; set; }
        public decimal TotalPrice { get; set; }
        public int Guests { get; set; }
        public class CreateBookingHandler : IRequestHandler<CreateBookingCommand, Guid>
        {
            private readonly IBookingRepository _repo;

            public CreateBookingHandler(IBookingRepository repo)
            {
                _repo = repo;
            }

            public async Task<Guid> Handle(CreateBookingCommand request, CancellationToken cancellationToken)
            {
                // Prevent double-booking
                var bookings = await _repo.GetByApartmentIdAsync(request.ApartmentId);
                if (bookings.Any(x => x.Status != Domain.Enums.BookingStatus.Cancelled &&
                    request.CheckIn < x.CheckOut && x.CheckOut < request.CheckOut))
                {
                    throw new Exception("Double-booking");
                }

                // Add new booking
                var booking = new Booking
                {
                    Id = Guid.NewGuid(),
                    ApartmentId = request.ApartmentId,
                    UserId = request.UserId,
                    CheckIn = request.CheckIn,
                    CheckOut = request.CheckOut,
                    TotalPrice = request.TotalPrice,
                    Guests = request.Guests,
                    Status = Domain.Enums.BookingStatus.Pending,

                    CreatedAt = DateTime.Now
                };

                await _repo.AddAsync(booking);
                return booking.Id;
            }
        }
    }
}
