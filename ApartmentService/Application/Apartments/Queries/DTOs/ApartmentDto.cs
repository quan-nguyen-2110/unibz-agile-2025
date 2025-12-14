using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Apartments.Queries.DTOs
{
    public class ApartmentDto
    {
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
        public List<string> Base64Images { get; set; } = new List<string>();

        public DateTime? AvailableFrom { get; set; }
        public string? Amenities { get; set; }
        public string Noisy { get; set; }
    }
}
