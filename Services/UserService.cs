//using Lucene.Net.Support;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RoleBasedAuthApi.Helpers;
using RoleBasedAuthApi.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace RoleBasedAuthApi.Services
{
    public interface IUserService
    {
        User Authenticate(string username, string password);
        IEnumerable<User> GetAll();
        User GetById(int id);
        User AddUser(User user);
    }
    public class UserService : IUserService
    {
        

        private readonly AppSettings _appSettings;
        private readonly RoleContext _context;

        public UserService(IOptions<AppSettings> appSettings, RoleContext context)
        {
            _appSettings = appSettings.Value;
            _context = context;
        }

        public User AddUser(User user)
        {           
            _context.users.Add(user);
            _context.SaveChanges();
            return user;
        }


        public User Authenticate(string username, string password)
        {
            var user = _context.users.ToList().SingleOrDefault(x => x.Username == username && x.Password == password);

            // return null if user not found
            if (user == null)
                return null;

            // authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString()),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.WriteToken(token);

            return user.WithoutPassword();
        }

        public IEnumerable<User> GetAll()
        {
            return _context.users.ToList().WithoutPasswords();
        }

        public User GetById(int id)
        {
            var user = _context.users.ToList().FirstOrDefault(x => x.Id == id);
            return user.WithoutPassword();
        }

    }
}
