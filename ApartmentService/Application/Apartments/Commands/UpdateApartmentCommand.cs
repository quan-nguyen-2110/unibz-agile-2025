using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using Domain.Entities;
using MediatR;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace Application.Apartments.Commands;

public class UpdateApartmentCommand : IRequest<bool>
{
    public Guid Id { get; set; }
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

    public UpdateApartmentCommand() { }

    public class UpdateApartmentHandler : IRequestHandler<UpdateApartmentCommand, bool>
    {
        private readonly IApartmentRepository _aptRepo;
        private readonly IApartmentImageRepository _aptImageRepo;
        private readonly IMessagePublisher _publisher;
        private readonly IConfiguration _config;

        public UpdateApartmentHandler(
            IApartmentRepository aptRepo,
            IApartmentImageRepository aptImageRepo,
            IMessagePublisher publisher,
            IConfiguration config)
        {
            _aptRepo = aptRepo;
            _aptImageRepo = aptImageRepo;
            _publisher = publisher;
            _config = config;
        }

        public async Task<bool> Handle(UpdateApartmentCommand request, CancellationToken cancellationToken)
        {
            var apt = await _aptRepo.GetByIdAsync(request.Id);
            if (apt == null)
                throw new KeyNotFoundException("Apartment not found");

            apt.Title = request.Title.Trim();
            apt.Address = request.Address.Trim();
            apt.Price = request.Price;
            apt.Area = request.Area;
            apt.Floor = request.Floor;
            apt.Bedrooms = request.Bedrooms;
            apt.Bathrooms = request.Bathrooms;
            apt.Description = request.Description?.Trim();
            apt.Amenities = request.Amenities?.Trim();
            apt.AvailableFrom = request.AvailableFrom;
            apt.Code = "";

            // Remove old images
            if (apt.ApartmentImages.Any())
            {
                await _aptImageRepo.RemoveRangeAsync(apt.ApartmentImages);
            }

            // Add new images
            await _aptImageRepo.AddRangeAsync(ApartmentImages.FromBase64List(request.Id, request.Base64Images));

            // Update apt
            await _aptRepo.UpdateAsync(apt);

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
                        Base64Image = request.Base64Images.FirstOrDefault()
                    }),
                    _config["RabbitMQ:RK:UpdateApartment"] ?? "rk-update-apt");
            }
            catch (Exception ex)
            {
                // Log the exception (logging mechanism not shown here)
                Console.WriteLine($"Failed to publish message: {ex.Message}");
            }

            return true;
        }
    }
}