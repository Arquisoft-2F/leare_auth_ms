using System.ComponentModel.DataAnnotations;
namespace SharedClassLibrary.DTOs
{
    public class UserDTO
    {
        [Required]
        public string Name { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public int Role { get; set; } = int.MaxValue;

        [Required]
        public string UserId { get; set; } = Guid.NewGuid().ToString();
    }
}
