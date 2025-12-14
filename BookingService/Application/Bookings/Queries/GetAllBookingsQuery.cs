using Application.Bookings.Queries.DTOs;
using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;

namespace Application.Bookings.Queries
{
    public class GetAllBookingsQuery : IRequest<List<BookingDto>>
    {

        public class GetAllBookingsHandler : IRequestHandler<GetAllBookingsQuery, List<BookingDto>>
        {
            private readonly IBookingRepository _repo;

            public GetAllBookingsHandler(IBookingRepository repo)
            {
                _repo = repo;
            }

            public async Task<List<BookingDto>> Handle(GetAllBookingsQuery request, CancellationToken cancellationToken)
            {
                var bookings = await _repo.GetAllAsync();
                List<BookingDto> bookingDtos = bookings.Select(booking => new BookingDto
                {
                    Id = booking.Id,

                    // Apartment
                    ApartmentId = booking.ApartmentId,
                    ApartmentTitle = booking.Apartment?.Title ?? "",
                    ApartmentImage = booking.Apartment?.Base64Image ?? "",
                    ApartmentAddress = booking.Apartment?.Address ?? "",
                    ApartmentPrice = booking.Apartment?.Price ?? 0,

                    // Booking
                    CheckIn = booking.CheckIn,
                    CheckOut = booking.CheckOut,
                    Guests = booking.Guests,
                    Nights = booking.CalculateNights(),
                    TotalPrice = booking.TotalPrice,
                    Status = booking.Status.ToString().ToLower(),
                    CreatedAt = booking.CreatedAt,
                    CancelReason = booking.CancelReason,

                    // User
                    UserId = booking.UserId,
                    UserName = booking.User?.Name ?? "Unknown User",
                    UserPhone = booking.User?.Phone ?? "Unknown Phone",
                    UserEmail = booking.User?.Email ?? "Unknown Email",
                }).ToList();

                return bookingDtos;
            }
        }


    }

}
