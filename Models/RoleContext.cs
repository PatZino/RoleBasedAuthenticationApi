using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RoleBasedAuthApi.Models
{
    public class RoleContext: DbContext
    {
        public RoleContext(DbContextOptions<RoleContext> options)
          : base(options)
        {
        }

        public DbSet<User> users { get; set; }
    }
}
