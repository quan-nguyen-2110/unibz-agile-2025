using Application.Interfaces.IMessaging;
using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;
using System.Text;

namespace Infrastructure.Messaging
{
    public class RabbitMqPublisher : IMessagePublisher
    {
        private readonly string _host;
        private readonly string _username;
        private readonly string _password;
        private readonly string _exchangeName;
        //private readonly string _RKCreatedApt;
        public RabbitMqPublisher(IConfiguration config)
        {
            _host = config["RabbitMQ:Host"] ?? "localhost";
            _username = config["RabbitMQ:User"] ?? "guest";
            _password = config["RabbitMQ:Pass"] ?? "guest";
            _exchangeName = config["RabbitMQ:ExchangeName"] ?? "rent-hub";
            //_RKCreatedApt = config["RabbitMQ:RK.CreateApartment"] ?? "apt-rounting-key";
        }

        public async Task PublishAsync(string message, string routingKey)
        {
            var factory = new ConnectionFactory()
            {
                HostName = _host,
                UserName = _username,
                Password = _password
            };

            using var connection = await factory.CreateConnectionAsync();
            using var channel = await connection.CreateChannelAsync();

            // Declare exchange if not exists
            await channel.ExchangeDeclareAsync(exchange: _exchangeName, type: ExchangeType.Direct);

            var body = Encoding.UTF8.GetBytes(message);

            // With default exchange, routingKey must equal queue name.
            /*Exchanges only route messages to queues based on bindings.

            If no queue is bound to the exchange, any message published to it will be dropped (lost).

            This is true for all exchange types (direct, topic, fanout, headers).*/
            //
            await channel.BasicPublishAsync(exchange: _exchangeName, routingKey: routingKey, body: body);
            Console.WriteLine($" [x] Sent {message}");

            await Task.CompletedTask;
        }
    }
}
