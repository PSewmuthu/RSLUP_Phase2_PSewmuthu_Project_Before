using System.ComponentModel.DataAnnotations;

namespace Authentication.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
