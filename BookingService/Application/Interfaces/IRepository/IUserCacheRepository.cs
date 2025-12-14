using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Interfaces.IRepository
{
    public interface IUserCacheRepository
    {
        Task<UserCache> AddAsync(UserCache user, CancellationToken ct = default);
        Task<int> UpdateAsync(UserCache user, CancellationToken ct = default);
        Task<bool> IsExistingAsync(Guid id, CancellationToken ct = default);
        Task DeleteAsync(Guid id);
    }
}
