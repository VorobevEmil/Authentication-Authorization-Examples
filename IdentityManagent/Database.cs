using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityManagent
{
    public class Database
    {
        private static string UserHash(string username) => Convert.ToBase64String(MD5.HashData(Encoding.UTF8.GetBytes(username)));

        public async Task<User?> GetUserAsync(string username)
        {
            var hash = UserHash(username);
            if (!File.Exists(hash))
            {
                return null;
            }

            await using var reader = File.OpenRead(hash);
            return await JsonSerializer.DeserializeAsync<User>(reader);
        }

        public async Task PutAsync(User user)
        {
            var hash = UserHash(user.Username);
            await using var writer = File.OpenWrite(hash);
            await JsonSerializer.SerializeAsync(writer, user);
        }
    }
    public class User
    {
        public string Username { get; set; } = default!;
        public string PasswordHash { get; set; } = default!;
        public List<UserClaim> Claims { get; set; } = new();
    }

    public class UserClaim
    {
        public string Type { get; set; } = default!;
        public string Value { get; set; } = default!;
    }
}
