using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Bookings.Queries.DTOs
{
    public class BookingDto
    {
        public Guid Id { get; set; }
        public Guid ApartmentId { get; set; }
        public string ApartmentTitle { get; set; } = default!;
        public string ApartmentImage { get; set; } = default!;
        public string ApartmentAddress { get; set; } = default!;
        public decimal ApartmentPrice { get; set; }

        public Guid UserId { get; set; }
        public string UserName { get; set; } = default!;
        public string UserEmail { get; set; } = default!;
        public string UserPhone { get; set; } = default!;

        public DateTime CheckIn { get; set; }
        public DateTime CheckOut { get; set; }
        public int Guests { get; set; }
        public int Nights { get; set; }
        public decimal TotalPrice { get; set; }
        public string Status { get; set; } = default!;
        public DateTime CreatedAt { get; set; }
        public string? CancelReason { get; set; }

    }
}
