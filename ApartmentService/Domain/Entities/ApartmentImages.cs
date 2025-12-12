using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class ApartmentImages
    {
        [Key]
        public Guid Id { get; set; }
        public Guid ApartmentId { get; set; }
        public required string Base64Image { get; set; }

        public virtual Apartment Apartment { get; set; } = default!;
        public static List<ApartmentImages> FromBase64List(Guid apartmentId, List<string> base64Images)
        {
            List<ApartmentImages> images = new List<ApartmentImages>();
            foreach (var base64 in base64Images)
            {
                images.Add(new ApartmentImages
                {
                    Id = Guid.NewGuid(),
                    ApartmentId = apartmentId,
                    Base64Image = base64
                });
            }
            return images;
        }
    }
}
