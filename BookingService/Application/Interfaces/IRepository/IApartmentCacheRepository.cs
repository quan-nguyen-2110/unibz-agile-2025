using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.IRepository
{
    public interface IApartmentCacheRepository
    {
        Task<ApartmentCache> AddAsync(ApartmentCache apartment, CancellationToken ct = default);
        Task<int> UpdateAsync(ApartmentCache apartment, CancellationToken ct = default);
        Task<bool> IsExistingAsync(Guid id, CancellationToken ct = default);
    }
}
