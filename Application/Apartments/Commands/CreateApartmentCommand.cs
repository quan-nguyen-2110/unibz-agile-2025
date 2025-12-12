using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using Domain.Entities;
using FluentValidation;
using MediatR;

namespace Application.Apartments.Commands;

public class CreateApartmentCommand : IRequest<Guid>
{
    public string Title { get; set; } = default!;
    public string Address { get; set; } = default!;
    public decimal Price { get; set; }
    public double Area { get; set; }
    public int Bedrooms { get; set; }
    public int Bathrooms { get; set; }
    public string? Description { get; set; }
    public string? Amenities { get; set; }
    public DateTime? AvailableFrom { get; set; }
    public List<string> Base64Images { get; set; }

    public string? Code { get; set; }
    public int Floor { get; set; }


    public CreateApartmentCommand() { }

    public class CreateApartmentHandler : IRequestHandler<CreateApartmentCommand, Guid>
    {
        private readonly IApartmentRepository _repo;
        //private readonly IMessagePublisher _publisher;

        public CreateApartmentHandler(IApartmentRepository repo)
        {
            _repo = repo;
        }

        public async Task<Guid> Handle(CreateApartmentCommand request, CancellationToken cancellationToken)
        {
            var newApartmentId = Guid.NewGuid();
            var apt = new Apartment
            {
                Id = newApartmentId,
                Title = request.Title.Trim(),
                Address = request.Address.Trim(),
                Price = request.Price,
                Area = request.Area,
                Floor = request.Floor,
                Bedrooms = request.Bedrooms,
                Bathrooms = request.Bathrooms,
                Description = request.Description?.Trim(),
                Amenities = request.Amenities?.Trim(),
                AvailableFrom = request.AvailableFrom,
                ApartmentImages = ApartmentImages.FromBase64List(newApartmentId, request.Base64Images),

                Code = request.Code,
            };

            await _repo.AddAsync(apt);

            

            return apt.Id;
        }
    }
}