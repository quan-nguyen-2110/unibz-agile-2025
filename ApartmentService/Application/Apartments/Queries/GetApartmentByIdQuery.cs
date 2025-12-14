using Application.Apartments.Queries.DTOs;
using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;

namespace Application.Apartments.Queries;

public class GetApartmentByIdQuery : IRequest<ApartmentDto?>
{
    public Guid Id { get; set; }

    public GetApartmentByIdQuery(Guid id)
    {
        Id = id;
    }

    public class GetApartmentByIdHandler : IRequestHandler<GetApartmentByIdQuery, ApartmentDto?>
    {
        private readonly IApartmentRepository _aptRepo;
        private readonly IApartmentImageRepository _aptImageRepo;

        public GetApartmentByIdHandler(IApartmentRepository repo, IApartmentImageRepository aptImgRepo)
        {
            _aptRepo = repo;
            _aptImageRepo = aptImgRepo;
        }

        public async Task<ApartmentDto?> Handle(GetApartmentByIdQuery request, CancellationToken cancellationToken)
        {
            var apart = await _aptRepo.GetByIdAsync(request.Id);
            return apart != null ? new ApartmentDto()
            {
                Id = apart.Id,
                Title = apart.Title,
                Address = apart.Address,
                Price = apart.Price,
                Area = apart.Area,
                Floor = apart.Floor,
                Bedrooms = apart.Bedrooms,
                Bathrooms = apart.Bathrooms,
                Description = apart.Description,
                Amenities = apart.Amenities,
                AvailableFrom = apart.AvailableFrom,
                Noisy = apart.Noisy.ToString().ToLower(),
                Base64Images = await _aptImageRepo.GetBase64ImagesByApartmentIdAsync(apart.Id),

                Code = apart.Code,
            } : null;
        }
    }
}