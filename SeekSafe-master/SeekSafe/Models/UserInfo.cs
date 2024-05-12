using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace SeekSafe.Models
{
    public class UserInfo
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "ID Number is required.")]
        [RegularExpression(@"^\d{8}$", ErrorMessage = "ID Number must be exactly 8 digits.")]
        public string userIDNum { get; set; }
    }
}
