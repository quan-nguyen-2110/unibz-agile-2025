using Application.Apartments.Queries;
using Infrastructure;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Register MediatR handlers
//builder.Services.AddMediatR(cfg =>
//{
//    // Provide the assembly that contains your handlers
//    cfg.RegisterServicesFromAssembly(typeof(GetAllApartmentsQuery).Assembly);
//});

Application.DependencyInjection.AddApplication(builder.Services);

// Infrastructure
builder.Services.AddInfrastructure(builder.Configuration);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    c.IncludeXmlComments(xmlPath);
});

// Application & Infrastructure
//builder.Services.AddMediatR(typeof(GetAllApartmentsQuery).Assembly);
//builder.Services.AddValidatorsFromAssembly(typeof(CreateApartmentValidator).Assembly);
//builder.Services.AddInfrastructure(builder.Configuration);

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:8080") // frontend URL
              .AllowAnyHeader()
              .AllowAnyMethod(); // GET, POST, PUT, DELETE
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
Console.WriteLine($"Environment: {app.Environment.EnvironmentName}");
if (!app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
    // Database.Migrate() will apply all pending migrations automatically when the app starts.
    // For development / staging environments only!
    // For production: prefer CI/CD migration step to have control and avoid accidental data loss.
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.Migrate();
    }
}

app.UseHttpsRedirection();

app.UseCors("AllowFrontend"); // Enable CORS

app.UseAuthorization();

app.MapControllers();

app.Run();

// docker-compose build api
// docker-compose up -d api

// dotnet ef migrations add InitialCreate -p Infrastructure -s Api
// dotnet ef database update -p Infrastructure -s Api
