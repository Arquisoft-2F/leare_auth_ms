using IdentityManagerServerApi.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SharedClassLibrary.Contracts;
using SharedClassLibrary.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static SharedClassLibrary.DTOs.ServiceResponses;
namespace IdentityManagerServerApi.Repositories
{
   public class AccountRepository(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration config)
        : IUserAccount
    {
    
        public async Task<GeneralResponse> CreateAccount(UserDTO userDTO)
        {
            if (userDTO is null) return new GeneralResponse(false, "Model is empty");
            var newUser = new ApplicationUser()
            {
                Name = userDTO.Name,
                Email = userDTO.Email,
                PasswordHash = userDTO.Password,
                UserName = userDTO.Email
            };
            var user = await userManager.FindByEmailAsync(newUser.Email);
            if (user is not null) return new GeneralResponse(false, "User registered already");

            var createUser = await userManager.CreateAsync(newUser!, userDTO.Password);
            if (!createUser.Succeeded) return new GeneralResponse(false, "Error occured.. please try again");

            if(userDTO.Role == 0)
            {
                var checkAdmin = await roleManager.FindByNameAsync("admin");
                if (checkAdmin is null)
                    await roleManager.CreateAsync(new IdentityRole() { Name = "admin" });
                await userManager.AddToRoleAsync(newUser, "admin");
                return new GeneralResponse(true, "Account Created");
            }
            else if(userDTO.Role == 1)
            {
                var checkStudent = await roleManager.FindByNameAsync("student");
                if (checkStudent is null)
                    await roleManager.CreateAsync(new IdentityRole() { Name = "student" });
                await userManager.AddToRoleAsync(newUser, "student");
                return new GeneralResponse(true, "Account Created");

            }
            else if (userDTO.Role == 2)
            {
                var checkTeacher = await roleManager.FindByNameAsync("teacher");
                if (checkTeacher is null)
                    await roleManager.CreateAsync(new IdentityRole() { Name = "teacher" });
                await userManager.AddToRoleAsync(newUser, "teacher");
                return new GeneralResponse(true, "Account Created");
            }
            else
            {
                return new GeneralResponse(false, "Error ocurred.. Change your role");
            }
        }

        public async Task<LoginResponse> LoginAccount(LoginDTO loginDTO)
        {
            if (loginDTO == null)
                return new LoginResponse(false, null!, "Login data is empty");

            var getUser = await userManager.FindByEmailAsync(loginDTO.Email);
            if (getUser is null)
                return new LoginResponse(false, null!, "User not found");

            bool checkUserPasswords = await userManager.CheckPasswordAsync(getUser, loginDTO.Password);
            if (!checkUserPasswords)
                return new LoginResponse(false, null!, "Invalid email/password");

            var getUserRole = await userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Name, getUser.Email, getUserRole.First());
            string token = await GenerateToken(userSession);
            return new LoginResponse(true, token!, "Login successful");
        }

        private async Task<string> GenerateToken(UserSession user)
        {
            var loggedUser = await userManager.FindByEmailAsync(user.Email);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, loggedUser.Id),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };
            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
