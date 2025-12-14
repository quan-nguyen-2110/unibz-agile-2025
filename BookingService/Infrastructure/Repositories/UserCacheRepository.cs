using Application.Interfaces.IRepository;
using Domain.Entities;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Repositories
{
    public class UserCacheRepository : IUserCacheRepository
    {
        private readonly AppDbContext _db;

        public UserCacheRepository(AppDbContext db)
        {
            _db = db;
        }
        public async Task<UserCache> AddAsync(UserCache user, CancellationToken ct = default)
        {
            _db.UserCaches.Add(user);
            await _db.SaveChangesAsync(ct);
            return user;
        }

        public async Task<int> UpdateAsync(UserCache user, CancellationToken ct = default)
        {
            _db.UserCaches.Update(user);
            return await _db.SaveChangesAsync(ct);
        }

        public async Task<bool> IsExistingAsync(Guid id, CancellationToken ct = default)
            => await _db.UserCaches.AnyAsync(x => x.Id == id);

        public async Task DeleteAsync(Guid id)
        {
            var apt = await _db.UserCaches.FindAsync(id);
            if (apt != null)
            {
                _db.UserCaches.Remove(apt);
                await _db.SaveChangesAsync();
            }
        }
    }
}
