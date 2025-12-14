using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using Domain.Entities;
using Domain.Enums;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

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
    public NoisyLevel Noisy { get; set; }


    public CreateApartmentCommand() { }

    public class CreateApartmentHandler : IRequestHandler<CreateApartmentCommand, Guid>
    {
        private readonly IApartmentRepository _repo;
        private readonly IMessagePublisher _publisher;
        private readonly IConfiguration _config;

        public CreateApartmentHandler(IApartmentRepository repo, IMessagePublisher publisher, IConfiguration config)
        {
            _repo = repo;
            _publisher = publisher;
            _config = config;
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
                Noisy = request.Noisy,
                ApartmentImages = ApartmentImages.FromBase64List(newApartmentId, request.Base64Images),

                Code = request.Code,
            };

            await _repo.AddAsync(apt);

            try
            {
                await _publisher.PublishAsync(
                    JsonSerializer.Serialize(new
                    {
                        Id = apt.Id,
                        Title = apt.Title,
                        Address = apt.Address,
                        Price = apt.Price,
                        Description = apt.Description,
                        Base64Image = apt.ApartmentImages.FirstOrDefault()?.Base64Image
                    }),
                    _config["RabbitMQ:RK:CreateApartment"] ?? "rk-create-apt");
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Console.WriteLine($"Failed to publish message: {ex.Message}");
            }

            return apt.Id;
        }
    }
}