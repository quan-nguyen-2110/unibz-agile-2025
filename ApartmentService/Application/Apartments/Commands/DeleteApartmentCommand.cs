using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using MediatR;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace Application.Apartments.Commands;

public class DeleteApartmentCommand : IRequest<bool>
{
    public Guid Id { get; set; }

    public DeleteApartmentCommand(Guid id)
    {
        Id = id;
    }

    public class DeleteApartmentHandler : IRequestHandler<DeleteApartmentCommand, bool>
    {
        private readonly IApartmentRepository _repo;
        private readonly IMessagePublisher _publisher;
        private readonly IConfiguration _config;

        public DeleteApartmentHandler(IApartmentRepository repo, IMessagePublisher publisher, IConfiguration config)
        {
            _repo = repo;
            _publisher = publisher;
            _config = config;
        }

        public async Task<bool> Handle(DeleteApartmentCommand request, CancellationToken cancellationToken)
        {
            await _repo.DeleteAsync(request.Id);
            try
            {
                await _publisher.PublishAsync(
                    JsonSerializer.Serialize(new
                    {
                        Id = request.Id,
                    }),
                    _config["RabbitMQ:RK:DeleteApartment"] ?? "rk-delete-apt");
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