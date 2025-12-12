using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.IRepository
{
    public interface IApartmentImageRepository
    {
        Task AddRangeAsync(IEnumerable<ApartmentImages> images);
        Task RemoveRangeAsync(IEnumerable<ApartmentImages> images);
        Task<List<ApartmentImages>> GetByApartmentIdAsync(Guid apartmentId);
        Task<List<string>> GetBase64ImagesByApartmentIdAsync(Guid apartmentId);
    }
}
