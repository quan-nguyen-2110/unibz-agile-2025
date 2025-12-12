using Application.Bookings.Queries.DTOs;
using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Bookings.Queries
{
    public class GetBookingsByApartmentIdQuery : IRequest<List<BookingDto>>
    {
        public Guid Id { get; set; }
        public class GetBookingsByApartmentIdHandler : IRequestHandler<GetBookingsByApartmentIdQuery, List<BookingDto>>
        {
            private readonly IBookingRepository _repo;

            public GetBookingsByApartmentIdHandler(IBookingRepository repo)
            {
                _repo = repo;
            }

            public async Task<List<BookingDto>> Handle(GetBookingsByApartmentIdQuery request, CancellationToken cancellationToken)
            {
                var result = await _repo.GetByApartmentIdAsync(request.Id);
                return result.Select(b => new BookingDto
                {
                    Id = b.Id,
                    UserId = b.UserId,
                    ApartmentId = b.ApartmentId,
                    CheckIn = b.CheckIn,
                    CheckOut = b.CheckOut,
                    Status = b.Status.ToString(),
                    CreatedAt = b.CreatedAt,
                }).ToList();
            }
        }
    }
}
