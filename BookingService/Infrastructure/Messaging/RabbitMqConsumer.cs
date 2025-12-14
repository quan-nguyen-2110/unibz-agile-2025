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
        private readonly string _RKUpdatedApt;
        private readonly string _RKDeletedApt;

        private readonly string _RKRegisteredUser;
        private readonly string _RKUpdatedUser;

        private readonly IConfiguration _config;

        public RabbitMqConsumer(IConfiguration config, IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
            _config = config;

            _exchangeName = config["RabbitMQ:ExchangeName"] ?? "rent-hub";
            _bookingQueue = config["RabbitMQ:BookingQueueName"] ?? "booking-queue";

            _RKCreatedApt = config["RabbitMQ:RK:CreateApartment"] ?? "rk-create-apt";
            _RKUpdatedApt = config["RabbitMQ:RK:UpdateApartment"] ?? "rk-update-apt";
            _RKDeletedApt = config["RabbitMQ:RK:DeleteApartment"] ?? "rk-delete-apt";

            _RKRegisteredUser = config["RabbitMQ:RK:RegisterUser"] ?? "rk-register-user";
            _RKUpdatedUser = config["RabbitMQ:RK:UpdateUser"] ?? "rk-update-user";
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
                        // binding queue apartment events
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKCreatedApt).Wait();
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKUpdatedApt).Wait();
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKDeletedApt).Wait();
                        // binding queue user events
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKRegisteredUser).Wait();
                        _channel.QueueBindAsync(_bookingQueue, _exchangeName, _RKUpdatedUser).Wait();

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
                            var msgJson = Encoding.UTF8.GetString(ea.Body.ToArray());

                            // User events
                            if (routingKey == _RKRegisteredUser || routingKey == _RKUpdatedUser)
                            {
                                // For now, just log the registered user event
                                Console.WriteLine($"Received user registration event: {msgJson}");
                                var user = JsonSerializer.Deserialize<UserCache>(msgJson, new JsonSerializerOptions
                                {
                                    PropertyNameCaseInsensitive = true
                                });
                                if (user != null)
                                {
                                    using var scope = _scopeFactory.CreateScope();
                                    var _userRepository = scope.ServiceProvider.GetRequiredService<IUserCacheRepository>();

                                    if (routingKey == _RKRegisteredUser)
                                        await _userRepository.AddAsync(user);
                                    else if (routingKey == _RKUpdatedUser)
                                    {
                                        var isExisting = await _userRepository.IsExistingAsync(user.Id);
                                        if (isExisting)
                                            await _userRepository.UpdateAsync(user);
                                        else
                                            await _userRepository.AddAsync(user);
                                    }
                                }
                            }
                            // Apartment events
                            else if (routingKey == _RKCreatedApt || routingKey == _RKUpdatedApt || routingKey == _RKDeletedApt)
                            {
                                var apt = JsonSerializer.Deserialize<ApartmentCache>(msgJson, new JsonSerializerOptions
                                {
                                    PropertyNameCaseInsensitive = true
                                });
                                if (apt != null)
                                {
                                    using var scope = _scopeFactory.CreateScope();
                                    var _aptRepository = scope.ServiceProvider.GetRequiredService<IApartmentCacheRepository>();

                                    if (routingKey == _RKCreatedApt)
                                        await _aptRepository.AddAsync(apt);
                                    else if (routingKey == _RKUpdatedApt)
                                    {
                                        var isExisting = await _aptRepository.IsExistingAsync(apt.Id);
                                        if (isExisting)
                                            await _aptRepository.UpdateAsync(apt);
                                        else
                                            await _aptRepository.AddAsync(apt);
                                    }
                                    else if (routingKey == _RKDeletedApt)
                                        await _aptRepository.DeleteAsync(apt.Id);
                                }
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
