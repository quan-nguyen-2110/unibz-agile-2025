using Application.Apartments.Queries.DTOs;
using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;

namespace Application.Apartments.Queries
{
    public class GetAllApartmentsQuery : IRequest<List<ApartmentDto>>
    {

        public class GetAllApartmentsHandler : IRequestHandler<GetAllApartmentsQuery, List<ApartmentDto>>
        {
            private readonly IApartmentRepository _aptRepo;
            private readonly IApartmentImageRepository _aptImageRepo;
            private readonly IMessagePublisher _publisher;

            public GetAllApartmentsHandler(IApartmentRepository repo, IApartmentImageRepository aptImgRepo, IMessagePublisher publisher)
            {
                _aptRepo = repo;
                _aptImageRepo = aptImgRepo;
                _publisher = publisher;
            }

            public async Task<List<ApartmentDto>> Handle(GetAllApartmentsQuery request, CancellationToken cancellationToken)
            {
                List<ApartmentDto> result = new List<ApartmentDto>();
                var apartments = await _aptRepo.GetAllAsync();
                foreach (var apt in apartments)
                {
                    ApartmentDto dto = new ApartmentDto
                    {
                        Id = apt.Id,
                        Title = apt.Title.Trim(),
                        Address = apt.Address.Trim(),
                        Floor = apt.Floor,
                        Area = apt.Area,
                        Price = apt.Price,
                        Bedrooms = apt.Bedrooms,
                        Bathrooms = apt.Bathrooms,
                        Description = apt.Description?.Trim(),
                        AvailableFrom = apt.AvailableFrom,
                        Amenities = apt.Amenities?.Trim(),

                        Base64Images = await _aptImageRepo.GetBase64ImagesByApartmentIdAsync(apt.Id),

                        Code = apt.Code,
                    };

                    result.Add(dto);
                }

                try
                {
                    await _publisher.PublishAsync("chau len ba", "chau di mau giao");
                }
                catch (Exception ex)
                {
                    var msg = ex.Message;
                }

                return result;
            }
        }
    }
}
