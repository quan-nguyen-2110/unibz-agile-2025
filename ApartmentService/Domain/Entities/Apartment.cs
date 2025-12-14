using Domain.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class Apartment
    {
        [Key]
        public Guid Id { get; set; }
        public string Code { get; set; } = default!;
        public string Address { get; set; } = default!;
        public int Floor { get; set; }
        public double Area { get; set; } // m2
        public decimal Price { get; set; }

        public string Title { get; set; } = default!;
        public int Bedrooms { get; set; }
        public int Bathrooms { get; set; }
        public string? Description { get; set; }

        public DateTime? AvailableFrom { get; set; }
        public string? Amenities { get; set; }
        public NoisyLevel Noisy { get; set; } = NoisyLevel.Moderate;

        public virtual List<ApartmentImages> ApartmentImages { get; set; } = new List<ApartmentImages>();
    }
}
