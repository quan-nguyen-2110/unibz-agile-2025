import { useParams, Link, useLocation, useNavigate } from "react-router-dom";
import { Navbar } from "@/components/Navbar";
import { mockApartments } from "@/data/apartments";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Bed,
  Bath,
  Maximize,
  MapPin,
  Calendar,
  ArrowLeft,
  Check,
  Edit,
  Save,
  X,
  Upload,
  Trash2,
  Building2,
  CalendarDays,
  Volume2,
} from "lucide-react";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar as CalendarComponent } from "@/components/ui/calendar";
import {
  areIntervalsOverlapping,
  format,
  isWithinInterval,
  subDays,
} from "date-fns";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { cn } from "@/lib/utils";
import axios from "axios";
import { Apartment, NoisyLevel } from "@/types/apartment";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Booking } from "@/types/booking";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const apartmentSchema = z.object({
  id: z.string().min(1, "ID is required"),
  title: z
    .string()
    .trim()
    .min(1, "Title is required")
    .max(100, "Title must be less than 100 characters"),
  address: z
    .string()
    .trim()
    .min(1, "Address is required")
    .max(200, "Address must be less than 200 characters"),
  price: z
    .number()
    .min(1, "Price must be at least $1")
    .max(1000000, "Price must be less than $1,000,000"),
  bedrooms: z
    .number()
    .min(0, "Bedrooms must be at least 0")
    .max(20, "Bedrooms must be less than 20"),
  bathrooms: z
    .number()
    .min(0, "Bathrooms must be at least 0")
    .max(20, "Bathrooms must be less than 20"),
  area: z
    .number()
    .min(1, "Area must be at least 1 sqft")
    .max(100000, "Area must be less than 100,000 sqft"),
  floor: z
    .number()
    .min(0, "Floor must be at least 0")
    .max(200, "Floor must be less than 200"),
  availableFrom: z.date().nullable().optional(),
  description: z
    .string()
    .trim()
    .min(1, "Description is required")
    .max(2000, "Description must be less than 2000 characters"),
  amenities: z.string().max(500, "Amenities must be less than 500 characters"),
  base64Images: z
    .array(z.string().min(1, "Image data cannot be empty"))
    .min(1, "At least one image is required"),
  noisy: z.string().trim().min(1, "At least one noisy level is selected"),
});

const API_APARTMENT_URL =
  (import.meta.env.VITE_APARTMENT_API_URL || "https://localhost:7147") +
  "/api/Apartment";

const API_BOOKING_URL =
  (import.meta.env.VITE_BOOKING_API_URL || "https://localhost:7221") +
  "/api/Bookings";

const ApartmentDetail = () => {
  const { id } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const originalApartment = location.state?.apartment;
  const [currentApartment, setCurrentApartment] =
    useState<Apartment>(originalApartment);
  const [selectedImage, setSelectedImage] = useState(0);
  const [isEditMode, setIsEditMode] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [editData, setEditData] = useState({
    title: "",
    address: "",
    price: "",
    bedrooms: "",
    bathrooms: "",
    area: "",
    floor: "",
    description: "",
    amenities: "",
    availableFrom: undefined as Date | undefined,
    base64Images: [] as string[],
    noisy: "moderate" as NoisyLevel,
  });
  const [bookingDialogOpen, setBookingDialogOpen] = useState(false);
  const [checkIn, setCheckIn] = useState("");
  const [checkOut, setCheckOut] = useState("");
  const [guests, setGuests] = useState(1);
  const [activeBookings, setActiveBookings] = useState<Booking[]>([]);

  // Get active bookings for this apartment (pending or confirmed, not cancelled)
  useEffect(() => {
    const fetchBookings = async () => {
      if (!currentApartment) {
        setActiveBookings([]);
        return;
      }

      setIsLoading(true);
      try {
        const response = await axios.get(
          `${API_BOOKING_URL}/apartment/${currentApartment.id}`
        );
        const allBookings: Booking[] = response.data;
        const filtered = allBookings.filter(
          (b) =>
            b.apartmentId === currentApartment.id && b.status !== "cancelled"
        );
        setActiveBookings(filtered);
      } catch (err) {
        toast.error(err.message);
        setActiveBookings([]);
      } finally {
        setIsLoading(false);
      }
    };

    const userRole = localStorage.getItem("userRole");
    if (userRole === "user") fetchBookings();
  }, [currentApartment, bookingDialogOpen]);

  useEffect(() => {
    const userRole = localStorage.getItem("userRole");
    setIsAdmin(userRole === "admin");

    if (!originalApartment) {
      const fetchApartment = async () => {
        setIsLoading(true);
        try {
          const response = await axios.get<Apartment>(
            `${API_APARTMENT_URL}/${id}`
          );

          setCurrentApartment(response.data);
        } catch (err) {
          toast.error(err.message);
        } finally {
          setIsLoading(false);
        }
      };

      fetchApartment();
    }
  }, [id, originalApartment]);

  // Check if a date range overlaps with existing bookings
  const hasBookingConflict = (
    checkInDate: Date,
    checkOutDate: Date
  ): boolean => {
    return activeBookings.some((booking) => {
      const existingStart = booking.checkIn;
      const existingEnd = booking.checkOut;
      return areIntervalsOverlapping(
        { start: checkInDate, end: checkOutDate },
        { start: existingStart, end: existingEnd }
      );
    });
  };

  // Check if a specific date is within any booked period
  const isDateBooked = (date: Date): boolean => {
    return activeBookings.some((booking) => {
      const start = booking.checkIn;
      const end = subDays(booking.checkOut, 1);
      return isWithinInterval(date, { start, end });
    });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <div className="container mx-auto px-4 py-8">
          <div className="animate-pulse space-y-4">
            <div className="h-10 w-32 bg-muted rounded" />
            <div className="h-96 bg-muted rounded-lg" />
            <div className="h-8 w-3/4 bg-muted rounded" />
            <div className="h-6 w-1/2 bg-muted rounded" />
          </div>
        </div>
      </div>
    );
  }

  if (!currentApartment) {
    return (
      <div className="min-h-screen bg-background">
        <Navbar />
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-between mb-6">
            <Link to="/">
              <Button variant="ghost" className="gap-2">
                <ArrowLeft className="h-4 w-4" />
                Back to listings
              </Button>
            </Link>
          </div>
        </div>
        <div className="container mx-auto px-4 py-8">
          <p className="text-center text-xl">Apartment not found</p>
        </div>
      </div>
    );
  }

  const handleContact = () => {
    toast.success("Contact request sent! We'll get back to you soon.");
  };

  const handleEdit = () => {
    setEditData({
      title: currentApartment.title,
      address: currentApartment.address,
      price: currentApartment.price.toString(),
      bedrooms: currentApartment.bedrooms.toString(),
      bathrooms: currentApartment.bathrooms.toString(),
      area: currentApartment.area.toString(),
      floor: currentApartment.floor.toString(),
      description: currentApartment.description,
      amenities: currentApartment.amenities,
      availableFrom: currentApartment.availableFrom,
      base64Images: [...currentApartment.base64Images],
      noisy: currentApartment.noisy,
    });
    setIsEditMode(true);
  };

  const handleCancel = () => {
    setIsEditMode(false);
  };

  const handleDelete = async () => {
    setIsLoading(true);
    try {
      const response = await axios.delete(
        `${API_APARTMENT_URL}/${currentApartment.id}`
      );
      console.log("Success:", response.data);
      toast.success(
        `Your Apartment ${currentApartment.title} has been deleted successfully.`
      );

      navigate("/");
    } catch (err) {
      toast.error(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleBooking = async () => {
    if (!checkIn || !checkOut) {
      toast.error("Please select check-in and check-out dates.");
      return;
    }

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    if (checkOutDate <= checkInDate) {
      toast.error("Check-out date must be after check-in date.");
      return;
    }

    // Check for booking conflicts
    if (hasBookingConflict(checkInDate, checkOutDate)) {
      toast.error(
        "This apartment is already booked for the selected dates. Please choose different dates."
      );
      return;
    }

    const nights = Math.ceil(
      (checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
    );
    const totalPrice = currentApartment.price * nights;

    const booking = {
      ApartmentId: currentApartment.id,
      CheckIn: checkIn,
      CheckOut: checkOut,
      Guests: guests,
      TotalPrice: totalPrice,

      // userId
      UserId:
        localStorage.getItem("userId") ||
        "00000000-0000-0000-0000-000000000000",
    };

    setIsLoading(true);
    try {
      const response = await axios.post(`${API_BOOKING_URL}`, booking);
      console.log("Success:", response.data);

      toast.success(
        `Your booking for ${nights} night${
          nights > 1 ? "s" : ""
        } has been submitted. Total: $${totalPrice.toLocaleString()}`
      );

      setBookingDialogOpen(false);
      setCheckIn("");
      setCheckOut("");
      setGuests(1);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      // Validate images
      if (editData.base64Images.length === 0) {
        toast.error("Please add at least one image");
        return;
      }

      // Validate the input
      const validatedData = apartmentSchema.parse({
        id: id,
        title: editData.title,
        address: editData.address,

        price: Number(editData.price),
        bedrooms: Number(editData.bedrooms),
        bathrooms: Number(editData.bathrooms),
        area: Number(editData.area),
        floor: Number(editData.floor),

        availableFrom: new Date(format(editData.availableFrom, "MMM dd, yyyy")),
        description: editData.description,
        amenities: editData.amenities,
        //base64Images: editData.base64Images,
        base64Images: [
          "/src/assets/apartment-1.jpg",
          "/src/assets/apartment-2.jpg",
          "/src/assets/apartment-3.jpg",
          "/src/assets/apartment-4.jpg",
        ],

        noisy: editData.noisy,
      });

      setIsSaving(true);
      const response = await axios.put(
        `${API_APARTMENT_URL}/${id}`,
        validatedData
      );

      // Update the current apartment with the new data
      const updatedApartment = {
        ...currentApartment,
        title: editData.title,
        address: editData.address,
        price: parseFloat(editData.price),
        bedrooms: parseInt(editData.bedrooms),
        bathrooms: parseFloat(editData.bathrooms),
        area: parseInt(editData.area),
        floor: parseInt(editData.floor),
        availableFrom: editData.availableFrom,
        description: editData.description,
        amenities: editData.amenities,
        base64Images: [...editData.base64Images],
        noisy: editData.noisy,
      };

      setCurrentApartment(updatedApartment);

      toast.success("Apartment updated successfully!");
      setIsEditMode(false);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const firstError = error.errors[0];
        toast.error(firstError.message);
      } else {
        toast.error("Failed to update apartment. Please check your inputs.");
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleEditChange = (
    field: string,
    value: number | Date | string | undefined
  ) => {
    setEditData((prev) => ({ ...prev, [field]: value }));
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const fileArray = Array.from(files);
    const validFiles: File[] = [];

    // Validate all files
    for (const file of fileArray) {
      if (!file.type.startsWith("image/")) {
        toast.error(`${file.name} is not an image file`);
        continue;
      }

      if (file.size > 5 * 1024 * 1024) {
        toast.error(`${file.name} is larger than 5MB`);
        continue;
      }

      validFiles.push(file);
    }

    if (validFiles.length === 0) return;

    // Read all valid files
    const newImages: string[] = [];
    let loadedCount = 0;

    validFiles.forEach((file) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        newImages.push(reader.result as string);
        loadedCount++;

        // Once all files are loaded, update state
        if (loadedCount === validFiles.length) {
          setEditData((prev) => ({
            ...prev,
            base64Images: [...prev.base64Images, ...newImages],
          }));
          toast.success(
            `${validFiles.length} image${
              validFiles.length > 1 ? "s" : ""
            } added successfully`
          );
        }
      };
      reader.readAsDataURL(file);
    });
  };

  const handleImageDelete = (index: number) => {
    setEditData((prev) => ({
      ...prev,
      base64Images: prev.base64Images.filter((_, i) => i !== index),
    }));
    // Reset selected image if it was deleted
    if (selectedImage === index) {
      setSelectedImage(0);
    } else if (selectedImage > index) {
      setSelectedImage(selectedImage - 1);
    }
    toast.success("Image removed");
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <Link to={`/${location.search}`}>
            <Button variant="ghost" className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              Back to listings
            </Button>
          </Link>

          {isAdmin &&
            (!isEditMode ? (
              <div className="flex gap-2">
                <Button onClick={handleEdit} className="gap-2">
                  <Edit className="h-4 w-4" />
                  Edit
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="destructive" className="gap-2">
                      <Trash2 className="h-4 w-4" />
                      Delete
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete Apartment</AlertDialogTitle>
                      <AlertDialogDescription>
                        Are you sure you want to delete "
                        {currentApartment.title}"? This action cannot be undone.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={handleDelete}
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      >
                        Delete
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            ) : (
              <div className="flex gap-2">
                <Button
                  onClick={handleSave}
                  className="gap-2"
                  disabled={isSaving}
                >
                  <Save className="h-4 w-4" />
                  {isSaving ? "Saving..." : "Save"}
                </Button>
                <Button
                  onClick={handleCancel}
                  variant="outline"
                  className="gap-2"
                  disabled={isSaving}
                >
                  <X className="h-4 w-4" />
                  Cancel
                </Button>
              </div>
            ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-6">
            {/* Main Image */}
            <div className="rounded-lg overflow-hidden shadow-lg">
              <img
                src={
                  isEditMode
                    ? editData.base64Images[selectedImage]
                    : currentApartment.base64Images[selectedImage]
                }
                alt={currentApartment.title}
                className="w-full h-96 object-cover"
              />
            </div>

            {/* Image Gallery */}
            {!isEditMode ? (
              <div className="grid grid-cols-4 gap-3">
                {currentApartment.base64Images.map((image, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedImage(index)}
                    className={cn(
                      "rounded-lg overflow-hidden border-2 transition-all",
                      selectedImage === index
                        ? "border-primary shadow-md"
                        : "border-transparent hover:border-muted"
                    )}
                  >
                    <img
                      src={image}
                      alt={`View ${index + 1}`}
                      className="w-full h-20 object-cover"
                    />
                  </button>
                ))}
              </div>
            ) : (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <Label className="text-lg font-semibold">Images</Label>
                  <label htmlFor="image-upload">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="gap-2"
                      asChild
                    >
                      <span>
                        <Upload className="h-4 w-4" />
                        Add Image(s)
                      </span>
                    </Button>
                  </label>
                  <input
                    id="image-upload"
                    type="file"
                    accept="image/jpeg, image/webp, image/jpg" // Restrict to common, small image types
                    multiple
                    className="hidden"
                    onChange={handleImageUpload}
                  />
                </div>
                <div className="grid grid-cols-4 gap-3">
                  {editData.base64Images.map((image, index) => (
                    <div
                      key={index}
                      className={cn(
                        "relative rounded-lg overflow-hidden border-2 transition-all group",
                        selectedImage === index
                          ? "border-primary shadow-md"
                          : "border-transparent hover:border-muted"
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => setSelectedImage(index)}
                        className="w-full"
                      >
                        <img
                          src={image}
                          alt={`View ${index + 1}`}
                          className="w-full h-20 object-cover"
                        />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleImageDelete(index)}
                        className="absolute top-1 right-1 bg-destructive text-destructive-foreground p-1.5 rounded-md opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                  {editData.base64Images.length === 0 && (
                    <div className="col-span-4 text-center py-8 border-2 border-dashed rounded-lg">
                      <p className="text-muted-foreground text-sm">
                        No images yet. Add some to get started.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Description */}
            <Card>
              <CardContent className="p-6">
                <h2 className="text-2xl font-bold mb-4">About this property</h2>
                {!isEditMode ? (
                  <p className="text-muted-foreground leading-relaxed">
                    {currentApartment.description}
                  </p>
                ) : (
                  <div className="space-y-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      value={editData.description}
                      onChange={(e) =>
                        handleEditChange("description", e.target.value)
                      }
                      className="min-h-32"
                    />
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Amenities */}
            <Card>
              <CardContent className="p-6">
                <h2 className="text-2xl font-bold mb-4">Amenities</h2>
                {!isEditMode ? (
                  <div className="grid grid-cols-2 gap-3">
                    {currentApartment.amenities
                      .split(",")
                      .map((a) => a.trim())
                      .filter((a) => a)
                      .map((amenity, index) => (
                        <div key={index} className="flex items-center gap-2">
                          <Check className="h-5 w-5 text-primary" />
                          <span>{amenity}</span>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label htmlFor="amenities">
                      Amenities (comma separated)
                    </Label>
                    <Input
                      id="amenities"
                      value={editData.amenities}
                      onChange={(e) =>
                        handleEditChange("amenities", e.target.value)
                      }
                      placeholder="e.g., Parking, Gym, Pool"
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <Card className="sticky top-20">
              <CardContent className="p-6 space-y-4">
                <div>
                  {!isEditMode ? (
                    <>
                      <h1 className="text-3xl font-bold mb-2">
                        {currentApartment.title}
                      </h1>
                      <div className="flex items-center gap-1 text-muted-foreground mb-4">
                        <MapPin className="h-4 w-4" />
                        <span>{currentApartment.address}</span>
                      </div>
                    </>
                  ) : (
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="title">Title</Label>
                        <Input
                          id="title"
                          value={editData.title}
                          onChange={(e) =>
                            handleEditChange("title", e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label htmlFor="address">Address</Label>
                        <Input
                          id="address"
                          value={editData.address}
                          onChange={(e) =>
                            handleEditChange("address", e.target.value)
                          }
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="py-4 border-t border-b">
                  {!isEditMode ? (
                    <div className="text-3xl font-bold text-primary mb-1">
                      ${currentApartment.price}
                      <span className="text-lg font-normal text-muted-foreground">
                        /month
                      </span>
                    </div>
                  ) : (
                    <div>
                      <Label htmlFor="price">Monthly Rent ($)</Label>
                      <Input
                        id="price"
                        type="number"
                        value={editData.price}
                        onChange={(e) =>
                          handleEditChange("price", e.target.value)
                        }
                      />
                    </div>
                  )}
                </div>

                <div className="space-y-3">
                  {!isEditMode ? (
                    <>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Bedrooms</span>
                        <div className="flex items-center gap-1 font-semibold">
                          <Bed className="h-4 w-4" />
                          {currentApartment.bedrooms}
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Bathrooms</span>
                        <div className="flex items-center gap-1 font-semibold">
                          <Bath className="h-4 w-4" />
                          {currentApartment.bathrooms}
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Area</span>
                        <div className="flex items-center gap-1 font-semibold">
                          <Maximize className="h-4 w-4" />
                          {currentApartment.area} sqft
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Floor</span>
                        <div className="flex items-center gap-1 font-semibold">
                          <Building2 className="h-4 w-4" />
                          {currentApartment.floor}
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Available</span>
                        <div className="flex items-center gap-1 font-semibold">
                          <Calendar className="h-4 w-4" />
                          {currentApartment.availableFrom
                            ? format(
                                currentApartment.availableFrom,
                                "MMM dd, yyyy"
                              )
                            : "Not Available"}
                        </div>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Noise</span>
                        <div className="flex items-center gap-1 font-semibold capitalize">
                          <Volume2 className="h-4 w-4" />
                          {currentApartment.noisy}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="bedrooms">Bedrooms</Label>
                        <Input
                          id="bedrooms"
                          type="number"
                          value={editData.bedrooms}
                          onChange={(e) =>
                            handleEditChange("bedrooms", e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label htmlFor="bathrooms">Bathrooms</Label>
                        <Input
                          id="bathrooms"
                          type="number"
                          step="0.5"
                          value={editData.bathrooms}
                          onChange={(e) =>
                            handleEditChange("bathrooms", e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label htmlFor="area">Area (sqft)</Label>
                        <Input
                          id="area"
                          type="number"
                          value={editData.area}
                          onChange={(e) =>
                            handleEditChange("area", e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label htmlFor="floor">Floor</Label>
                        <Input
                          id="floor"
                          type="number"
                          value={editData.floor}
                          onChange={(e) =>
                            handleEditChange("floor", e.target.value)
                          }
                        />
                      </div>
                      <div>
                        <Label>Available From</Label>
                        <p className="text-xs text-muted-foreground mb-2">
                          Leave empty to mark as not available
                        </p>
                        <Popover>
                          <PopoverTrigger asChild>
                            <Button
                              variant="outline"
                              className={cn(
                                "w-full justify-start text-left font-normal",
                                !editData.availableFrom &&
                                  "text-muted-foreground"
                              )}
                            >
                              <Calendar className="mr-2 h-4 w-4" />
                              {editData.availableFrom ? (
                                format(editData.availableFrom, "PPP")
                              ) : (
                                <span>Not available</span>
                              )}
                            </Button>
                          </PopoverTrigger>
                          <PopoverContent className="w-auto p-0" align="start">
                            <CalendarComponent
                              mode="single"
                              selected={editData.availableFrom}
                              onSelect={(date) =>
                                handleEditChange("availableFrom", date)
                              }
                              initialFocus
                              className="pointer-events-auto"
                            />
                          </PopoverContent>
                        </Popover>
                        {editData.availableFrom && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              handleEditChange("availableFrom", null)
                            }
                            className="mt-1"
                          >
                            Clear date
                          </Button>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="noisy">Noise</Label>
                        <Select
                          value={editData.noisy}
                          onValueChange={(value: NoisyLevel) =>
                            handleEditChange("noisy", value)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select noise level" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="quiet">Quiet</SelectItem>
                            <SelectItem value="moderate">Moderate</SelectItem>
                            <SelectItem value="noisy">Noisy</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  )}
                </div>

                {!isEditMode && (
                  <div className="space-y-3 mt-6">
                    {isAdmin === false && (
                      <>
                        {currentApartment.availableFrom !== null ? (
                          <Dialog
                            open={bookingDialogOpen}
                            onOpenChange={setBookingDialogOpen}
                          >
                            <DialogTrigger asChild>
                              <Button size="lg" className="w-full">
                                <CalendarDays className="h-5 w-5 mr-2" />
                                Book Now
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[425px]">
                              <DialogHeader>
                                <DialogTitle>
                                  Book {currentApartment.title}
                                </DialogTitle>
                                <DialogDescription>
                                  ${currentApartment.price.toLocaleString()}
                                  /month
                                </DialogDescription>
                              </DialogHeader>
                              <div className="grid gap-4 py-4">
                                <div className="grid gap-2">
                                  <Label>Check-in Date</Label>
                                  <Popover>
                                    <PopoverTrigger asChild>
                                      <Button
                                        variant="outline"
                                        className={cn(
                                          "w-full justify-start text-left font-normal",
                                          !checkIn && "text-muted-foreground"
                                        )}
                                      >
                                        <CalendarDays className="mr-2 h-4 w-4" />
                                        {checkIn ? (
                                          format(new Date(checkIn), "PPP")
                                        ) : (
                                          <span>Select check-in date</span>
                                        )}
                                      </Button>
                                    </PopoverTrigger>
                                    <PopoverContent
                                      className="w-auto p-0"
                                      align="start"
                                    >
                                      <CalendarComponent
                                        mode="single"
                                        selected={
                                          checkIn
                                            ? new Date(checkIn)
                                            : undefined
                                        }
                                        onSelect={(date) =>
                                          setCheckIn(
                                            date
                                              ? format(date, "yyyy-MM-dd")
                                              : ""
                                          )
                                        }
                                        disabled={(date) => {
                                          const today = new Date();
                                          today.setHours(0, 0, 0, 0);
                                          const availableDate =
                                            currentApartment.availableFrom
                                              ? new Date(
                                                  currentApartment.availableFrom
                                                )
                                              : today;
                                          const minDate =
                                            today > availableDate
                                              ? today
                                              : availableDate;
                                          if (date < minDate) return true;
                                          return isDateBooked(date);
                                        }}
                                        initialFocus
                                        className="pointer-events-auto"
                                      />
                                    </PopoverContent>
                                  </Popover>
                                  {currentApartment.availableFrom && (
                                    <p className="text-xs text-muted-foreground">
                                      Available from{" "}
                                      {format(
                                        currentApartment.availableFrom,
                                        "MMM dd, yyyy"
                                      )}
                                    </p>
                                  )}
                                </div>
                                <div className="grid gap-2">
                                  <Label>Check-out Date</Label>
                                  <Popover>
                                    <PopoverTrigger asChild>
                                      <Button
                                        variant="outline"
                                        className={cn(
                                          "w-full justify-start text-left font-normal",
                                          !checkOut && "text-muted-foreground"
                                        )}
                                      >
                                        <CalendarDays className="mr-2 h-4 w-4" />
                                        {checkOut ? (
                                          format(new Date(checkOut), "PPP")
                                        ) : (
                                          <span>Select check-out date</span>
                                        )}
                                      </Button>
                                    </PopoverTrigger>
                                    <PopoverContent
                                      className="w-auto p-0"
                                      align="start"
                                    >
                                      <CalendarComponent
                                        mode="single"
                                        selected={
                                          checkOut
                                            ? new Date(checkOut)
                                            : undefined
                                        }
                                        onSelect={(date) =>
                                          setCheckOut(
                                            date
                                              ? format(date, "yyyy-MM-dd")
                                              : ""
                                          )
                                        }
                                        disabled={(date) => {
                                          const today = new Date();
                                          today.setHours(0, 0, 0, 0);
                                          const checkInDate = checkIn
                                            ? new Date(checkIn)
                                            : null;
                                          const minDate = checkInDate || today;
                                          if (date <= minDate) return true;
                                          return isDateBooked(date);
                                        }}
                                        initialFocus
                                        className="pointer-events-auto"
                                      />
                                    </PopoverContent>
                                  </Popover>
                                </div>
                                <div className="grid gap-2">
                                  <Label htmlFor="guests">
                                    Number of Guests
                                  </Label>
                                  <Input
                                    id="guests"
                                    type="number"
                                    min="1"
                                    value={guests}
                                    onChange={(e) =>
                                      setGuests(parseInt(e.target.value) || 1)
                                    }
                                  />
                                </div>
                              </div>
                              <DialogFooter>
                                <Button type="submit" onClick={handleBooking}>
                                  Confirm Booking
                                </Button>
                              </DialogFooter>
                            </DialogContent>
                          </Dialog>
                        ) : (
                          <Button size="lg" className="w-full" disabled>
                            <CalendarDays className="h-5 w-5 mr-2" />
                            Not Available for Booking
                          </Button>
                        )}
                      </>
                    )}
                    <Button
                      onClick={handleContact}
                      variant={isAdmin === false ? "outline" : "default"}
                      className="w-full"
                      size="lg"
                    >
                      Contact Owner
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApartmentDetail;
