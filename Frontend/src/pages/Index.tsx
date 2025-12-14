import { useState, useMemo, useEffect } from "react";
import { Navbar } from "@/components/Navbar";
import { ApartmentCard } from "@/components/ApartmentCard";
import { FilterSection, FilterState } from "@/components/FilterSection";
import { mockApartments } from "@/data/apartments";
import axios from "axios";
import { Apartment } from "@/types/apartment";
import { toast } from "sonner";
import { useSearchParams } from "react-router-dom";
import { format } from "date-fns";

const API_APARTMENT_URL =
  (import.meta.env.VITE_APARTMENT_API_URL || "https://localhost:7147") +
  "/api/Apartment";

const Index = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [isFiltering, setIsFiltering] = useState(false);

  const [filters, setFilters] = useState<FilterState>(() => ({
    bedrooms: searchParams.get("bedrooms") || "all",
    address: searchParams.get("address") || "",
    date: searchParams.get("date")
      ? new Date(searchParams.get("date")!)
      : undefined,
    maxPrice: searchParams.get("maxPrice") || "",
    noisy: searchParams.get("noisy") || "all",
  }));

  const [apartments, setApartments] = useState<Apartment[]>([]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.bedrooms !== "all") params.set("bedrooms", filters.bedrooms);
    if (filters.address) params.set("address", filters.address);
    if (filters.date) params.set("date", format(filters.date, "yyyy-MM-dd"));
    if (filters.maxPrice) params.set("maxPrice", filters.maxPrice);
    if (filters.noisy !== "all") params.set("noisy", filters.noisy);
    setSearchParams(params, { replace: true });

    const fetchApartments = async () => {
      setIsFiltering(true);
      try {
        const response = await axios.get<Apartment[]>(`${API_APARTMENT_URL}`);

        setApartments(response.data);
      } catch (err) {
        toast.error(err.message);
      } finally {
        setIsFiltering(false);
      }
    };

    fetchApartments();
  }, [filters, setSearchParams]);

  const filteredApartments = useMemo(() => {
    // return mockApartments.filter(apartment => {
    return apartments.filter((apartment) => {
      // Filter by bedrooms
      if (filters.bedrooms !== "all") {
        const bedroomCount = parseInt(filters.bedrooms);
        if (bedroomCount === 3 && apartment.bedrooms < 3) return false;
        if (bedroomCount !== 3 && apartment.bedrooms !== bedroomCount)
          return false;
      }

      // Filter by address
      if (
        filters.address &&
        !apartment.address.toLowerCase().includes(filters.address.toLowerCase())
      ) {
        return false;
      }

      // Filter by max price
      if (filters.maxPrice && apartment.price > parseInt(filters.maxPrice)) {
        return false;
      }

      // Filter by date
      if (filters.date && apartment.availableFrom > filters.date) {
        return false;
      }

      // Filter by noisy level
      if (filters.noisy !== "all" && apartment.noisy !== filters.noisy) {
        return false;
      }

      return true;
    });
  }, [filters, apartments]);

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">Find Your Perfect Home</h1>
          <p className="text-muted-foreground text-lg">
            Browse through {mockApartments.length} available apartments
          </p>
        </div>

        <div className="grid lg:grid-cols-4 gap-6">
          <aside className="lg:col-span-1">
            <FilterSection onFilterChange={setFilters} filtersProps={filters} />
          </aside>

          <main className="lg:col-span-3">
            {isFiltering ? (
              <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-6">
                {[1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className="h-96 bg-muted animate-pulse rounded-lg"
                  />
                ))}
              </div>
            ) : filteredApartments.length > 0 ? (
              <>
                <p className="text-muted-foreground mb-4">
                  Showing {filteredApartments.length}{" "}
                  {filteredApartments.length === 1 ? "apartment" : "apartments"}
                </p>
                <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-6">
                  {filteredApartments.map((apartment) => (
                    <ApartmentCard key={apartment.id} apartment={apartment} />
                  ))}
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <p className="text-xl text-muted-foreground">
                  No apartments match your filters
                </p>
                <p className="text-sm text-muted-foreground mt-2">
                  Try adjusting your search criteria
                </p>
              </div>
            )}
          </main>
        </div>
      </div>
    </div>
  );
};

export default Index;
