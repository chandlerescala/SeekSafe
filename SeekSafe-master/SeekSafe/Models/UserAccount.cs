using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace SeekSafe.Models
{
    public class UserAccount
    {
        [Required]
        [RegularExpression(@"^\d{8}$", ErrorMessage = "User ID Number must be exactly 8 digits.")]
        public string userIDNum { get; set; }

        [Required(ErrorMessage = "Username is required")]
        public string username { get; set; }
    }
}