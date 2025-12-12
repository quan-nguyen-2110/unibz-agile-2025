using Domain.Entities;

namespace Application.Interfaces.IRepository;

public interface IApartmentRepository
{
    Task<Apartment?> GetByIdAsync(Guid id);
    Task<List<Apartment>> GetAllAsync();
    Task<Guid> AddAsync(Apartment apt);
    Task UpdateAsync(Apartment apt);
    Task DeleteAsync(Guid id);

    
}
