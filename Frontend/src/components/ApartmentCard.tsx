import { Link, useLocation } from "react-router-dom";
import { Apartment } from "@/types/apartment";
import { Card, CardContent } from "./ui/card";
import { Badge } from "./ui/badge";
import { Bed, Bath, Maximize, MapPin, Building2 } from "lucide-react";

interface ApartmentCardProps {
  apartment: Apartment;
}

export const ApartmentCard = ({ apartment }: ApartmentCardProps) => {
  const location = useLocation();
  return (
    <Link to={`/apartment/${apartment.id}${location.search}`} state={{ apartment }}>
      <Card className="overflow-hidden hover:shadow-lg transition-all duration-300 cursor-pointer group">
        <div className="relative h-64 overflow-hidden">
          <img
            src={apartment.base64Images[0]}
            alt={apartment.title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
          <div className="absolute top-3 right-3">
            <Badge className="bg-primary text-primary-foreground font-semibold">
              ${apartment.price}/mo
            </Badge>
          </div>
        </div>
        <CardContent className="p-5">
          <h3 className="text-xl font-bold mb-2 text-foreground">
            {apartment.title}
          </h3>
          <div className="flex items-center gap-1 text-muted-foreground mb-3">
            <MapPin className="h-4 w-4" />
            <span className="text-sm">{apartment.address}</span>
          </div>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-1">
              <Bed className="h-4 w-4" />
              <span>{apartment.bedrooms} Beds</span>
            </div>
            <div className="flex items-center gap-1">
              <Bath className="h-4 w-4" />
              <span>{apartment.bathrooms} Baths</span>
            </div>
            <div className="flex items-center gap-1">
              <Maximize className="h-4 w-4" />
              <span>{apartment.area} sqft</span>
            </div>
            <div className="flex items-center gap-1">
              <Building2 className="h-4 w-4" />
              <span>Floor {apartment.floor}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
};
