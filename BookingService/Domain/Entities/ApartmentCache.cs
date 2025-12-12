using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class ApartmentCache
    {
        [Key]
        public Guid Id { get; set; }
        public string Address { get; set; } = default!;
        public string Title { get; set; } = default!;
        public decimal Price { get; set; }
        public string? Description { get; set; }
        public string Base64Image { get; set; } = default!;
    }
}
