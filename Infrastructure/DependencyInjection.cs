using Application.Interfaces.IMessaging;
using Application.Interfaces.IRepository;
using Infrastructure.Messaging;
using Infrastructure.Persistence;
using Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(config.GetConnectionString("Default")));

        services.AddScoped<IApartmentRepository, ApartmentRepository>();
        services.AddScoped<IApartmentImageRepository, ApartmentImageRepository>();

        //services.Configure<RabbitMqOptions>(config.GetSection("RabbitMQ"));
        services.AddSingleton<IMessagePublisher, RabbitMqPublisher>();
        //services.AddHostedService<RabbitMqConsumer>();

        return services;
    }
}
