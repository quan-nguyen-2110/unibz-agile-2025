using Application.Interfaces.IMessaging;
using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Messaging
{
    public class RabbitMqPublisher : IMessagePublisher
    {
        private readonly string _host;
        private readonly string _username;
        private readonly string _password;
        private readonly string _exchangeName;
        private readonly string _bkRountingKey;
        public RabbitMqPublisher(IConfiguration config)
        {
            _host = config["RabbitMQ:Host"] ?? "localhost";
            _username = config["RabbitMQ:User"] ?? "guest";
            _password = config["RabbitMQ:Pass"] ?? "guest";
            _exchangeName = config["RabbitMQ:ExchangeName"] ?? "rent-hub";
            _bkRountingKey = config["RabbitMQ:BkRountingKey"] ?? "bk-rounting-key";
        }
        public async Task PublishAsync(string message, string queue)
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
            await channel.ExchangeDeclareAsync(exchange: _exchangeName, type: ExchangeType.Fanout);

            var body = Encoding.UTF8.GetBytes(message);

            // With default exchange, routingKey must equal queue name.
            //
            await channel.BasicPublishAsync(exchange: _exchangeName, routingKey: _bkRountingKey, body: body);
            Console.WriteLine($" [x] Sent {message}");

            await Task.CompletedTask;
        }
    }
}
