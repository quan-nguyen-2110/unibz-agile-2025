using Application.Interfaces.IRepository;
using Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using System.Text;
using System.Text.Json;

namespace Infrastructure.Messaging
{
    public class RabbitMqConsumer : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private IConnection? _connection;
        private IChannel? _channel;

        private readonly string _exchangeName;
        private readonly string _bookingQueue;

        private readonly string _RKCreatedApt;
        private readonly string _RKUpdateddApt;

        private readonly IConfiguration _config;

        public RabbitMqConsumer(IConfiguration config, IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
            _config = config;

            _exchangeName = config["RabbitMQ:ExchangeName"] ?? "rent-hub";
            _bookingQueue = config["RabbitMQ:BookingQueueName"] ?? "booking-queue";
            _RKCreatedApt = config["RabbitMQ:RK:CreateApartment"] ?? "rk-create-apt";
            _RKUpdateddApt = config["RabbitMQ:RK:UpdateApartment"] ?? "rk-update-apt";
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Keep trying until RabbitMQ is available
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (_connection == null || !_connection.IsOpen)
                    {
                        var factory = new ConnectionFactory()
                        {
                            HostName = _config["RabbitMQ:Host"] ?? "rabbitmq",
                            Port = int.Parse(_config["RabbitMQ:Port"] ?? "5672"),
                            UserName = _config["RabbitMQ:User"] ?? "guest",
                            Password = _config["RabbitMQ:Pass"] ?? "guest"
                        };

                        Console.WriteLine("Attempting to connect to RabbitMQ...");
                        _connection = factory.CreateConnectionAsync().GetAwaiter().GetResult();
                        _channel = _connection.CreateChannelAsync().GetAwaiter().GetResult();

                        // declare exchange and queue
                        _channel.ExchangeDeclareAsync(exchange: _exchangeName, type: ExchangeType.Direct).Wait();
                        _channel.QueueDeclareAsync(
                            queue: _bookingQueue,
                            durable: false,
                            exclusive: false,
                            autoDelete: false,
                            arguments: null
                        ).Wait();
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKCreatedApt).Wait();
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKUpdateddApt).Wait();

                        Console.WriteLine("Connected to RabbitMQ!");
                    }

                    // setup consumer
                    // With this null-check to ensure _channel is not null before passing it to the constructor:
                    if (_channel == null)
                        throw new InvalidOperationException("RabbitMQ channel is not initialized.");
                    var consumer = new AsyncEventingBasicConsumer(_channel);
                    consumer.ReceivedAsync += async (model, ea) =>
                    {
                        try
                        {
                            var routingKey = ea.RoutingKey;
                            var aptJson = Encoding.UTF8.GetString(ea.Body.ToArray());
                            var apt = JsonSerializer.Deserialize<ApartmentCache>(aptJson);

                            if (apt != null)
                            {
                                using var scope = _scopeFactory.CreateScope();
                                var _aptRepository = scope.ServiceProvider.GetRequiredService<IApartmentCacheRepository>();
                                var isExisting = await _aptRepository.IsExistingAsync(apt.Id);

                                if (!isExisting)
                                    await _aptRepository.AddAsync(apt);
                                else
                                    await _aptRepository.UpdateAsync(apt);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error processing message: {ex.Message}");
                        }

                        await Task.Yield();
                    };

                    await _channel.BasicConsumeAsync(_bookingQueue, autoAck: true, consumer);

                    // Exit loop once connected and consuming
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Cannot connect to RabbitMQ. Retrying in 5 seconds... Error: {ex.Message}");
                    await Task.Delay(5000, stoppingToken); // wait 5 seconds before retry
                }
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _channel?.CloseAsync();
            _connection?.CloseAsync();
            return base.StopAsync(cancellationToken);
        }
    }


    //public RabbitMqConsumer(IConfiguration config, IServiceScopeFactory scopeFactory)
    //{
    //    _scopeFactory = scopeFactory;

    //    var factory = new ConnectionFactory()
    //    {
    //        HostName = config["RabbitMQ:Host"] ?? "localhost",
    //        Port = int.Parse(config["RabbitMQ:Port"] ?? "5672"),
    //        UserName = config["RabbitMQ:User"] ?? "guest",
    //        Password = config["RabbitMQ:Pass"] ?? "guest"
    //    };

    //    _exchangeName = config["RabbitMQ:ExchangeName"] ?? "rent-hub";
    //    _bookingQueue = config["RabbitMQ:BookingQueueName"] ?? "booking-queue";

    //    _RKCreatedApt = config["RabbitMQ:RK:CreateApartment"] ?? "rk-create-apt";
    //    _RKUpdateddApt = config["RabbitMQ:RK:UpdateApartment"] ?? "rk-update-apt";

    //    // Add this to confirm everything loads:
    //    Console.WriteLine("RabbitMQ host: " + factory.HostName);
    //    Console.WriteLine("Exchange: " + _exchangeName);
    //    Console.WriteLine("Queue: " + _bookingQueue);
    //    Console.WriteLine("RK Create Apt: " + _RKCreatedApt);
    //    Console.WriteLine("RK Update Apt: " + _RKUpdateddApt);
    //    //

    //    _connection = factory.CreateConnectionAsync().GetAwaiter().GetResult();
    //    _channel = _connection.CreateChannelAsync().GetAwaiter().GetResult();

    //    // declare exchange
    //    _channel.ExchangeDeclareAsync(exchange: _exchangeName, type: ExchangeType.Direct).Wait();

    //    // declare queue
    //    _channel.QueueDeclareAsync(
    //        queue: _bookingQueue,
    //        durable: false,
    //        exclusive: false,
    //        autoDelete: false,
    //        arguments: null
    //    ).Wait();

    //    // binding queue to exchange
    //    _channel.QueueBindAsync(queue: _bookingQueue, exchange: _exchangeName, routingKey: _RKCreatedApt).Wait();
    //    _channel.QueueBindAsync(queue: _bookingQueue, exchange: _exchangeName, routingKey: _RKUpdateddApt).Wait();
    //}

    //protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    //{
    //    var consumer = new AsyncEventingBasicConsumer(_channel);

    //    consumer.ReceivedAsync += async (model, ea) =>
    //    {
    //        try
    //        {
    //            // Get routing key
    //            var routingKey = ea.RoutingKey;

    //            var aptJson = Encoding.UTF8.GetString(ea.Body.ToArray());
    //            var apt = JsonSerializer.Deserialize<ApartmentCache>(aptJson);

    //            if (apt != null)
    //            {
    //                using var scope = _scopeFactory.CreateScope();

    //                var _aptRepository = scope.ServiceProvider.GetRequiredService<IApartmentCacheRepository>();
    //                var isExisting = await _aptRepository.IsExistingAsync(apt.Id);
    //                if (!isExisting)
    //                {
    //                    // handle create event
    //                    await _aptRepository.AddAsync(apt);
    //                }
    //                else
    //                {
    //                    // handle update event
    //                    await _aptRepository.UpdateAsync(apt);
    //                }

    //                //if (routingKey == _RKCreatedApt)
    //                //{
    //                //    // handle create event
    //                //    _aptRepository.AddAsync(apt).Wait();
    //                //}
    //                //else if (routingKey == _RKUpdateddApt)
    //                //{
    //                //    // handle update event
    //                //    var result = await _aptRepository.UpdateAsync(apt);
    //                //}
    //            }

    //        }
    //        catch (Exception ex)
    //        {
    //            Console.WriteLine(ex.Message);
    //        }


    //        await Task.Yield();
    //    };

    //    await _channel.BasicConsumeAsync(_bookingQueue, autoAck: true, consumer);
    //}
}
