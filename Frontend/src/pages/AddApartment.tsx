import { useEffect, useState } from "react";
import { Navbar } from "@/components/Navbar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { CalendarIcon, ArrowLeft, Upload, X } from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import axios from "axios";
import { NoisyLevel } from "@/types/apartment";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const API_APARTMENT_URL =
  (import.meta.env.VITE_APARTMENT_API_URL || "https://localhost:7147") +
  "/api/Apartment";

const AddApartment = () => {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [formData, setFormData] = useState({
    title: "",
    address: "",
    price: 0,
    area: 0,
    floor: 0,
    bedrooms: 0,
    bathrooms: 0,
    description: "",
    amenities: "",
    availableFrom: undefined as Date | undefined,
    noisy: "moderate" as NoisyLevel,

    //testing
    code: "a2",
  });

  const [base64Images, setBase64Images] = useState<string[]>([]);

  useEffect(() => {
    const userRole = localStorage.getItem("userRole");
    if (userRole !== "admin") {
      toast.error("Only admin users can add apartments");
      navigate("/");
    }
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (base64Images.length === 0) {
      toast.error("Please add at least one image");
      return;
    }

    const payload = {
      ...formData,
      price: Number(formData.price),
      area: Number(formData.area),
      floor: Number(formData.floor),
      bedrooms: Number(formData.bedrooms),
      bathrooms: Number(formData.bathrooms),
      availableFrom: formData.availableFrom
        ? format(formData.availableFrom, "yyyy-MM-dd")
        : null,
      //base64Images: base64Images,
      base64Images: [
        "/src/assets/apartment-1.jpg",
        "/src/assets/apartment-2.jpg",
        "/src/assets/apartment-3.jpg",
        "/src/assets/apartment-4.jpg",
      ],
    };

    try {
      setIsSubmitting(true);
      const response = await axios.post(`${API_APARTMENT_URL}`, payload);
      console.log("Success:", response.data);

      setFormData({
        title: "",
        address: "",
        price: 0,
        bedrooms: 0,
        bathrooms: 0,
        area: 0,
        floor: 0,
        description: "",
        amenities: "",
        availableFrom: undefined,
        noisy: "moderate",

        code: "a2",
      });
      setBase64Images([]);

      toast.success("Apartment listing created successfully!");

      setIsSubmitting(false);
    } catch (error) {
      toast.error("Error submitting property:", error);
    }
  };

  const handleChange = (field: string, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    Array.from(files).forEach((file) => {
      // Validate file type
      if (!file.type.startsWith("image/")) {
        toast.error(`${file.name} is not an image file`);
        return;
      }

      // Validate file size (10MB)
      if (file.size > 10 * 1024 * 1024) {
        toast.error(`${file.name} is too large. Maximum size is 10MB`);
        return;
      }

      // Create preview URL
      const reader = new FileReader();
      reader.onload = (e) => {
        const result = e.target?.result as string;
        setBase64Images((prev) => [...prev, result]);
        toast.success("Image added successfully");
      };
      reader.readAsDataURL(file);
    });

    // Reset input
    e.target.value = "";
  };

  const handleImageDelete = (index: number) => {
    setBase64Images((prev) => prev.filter((_, i) => i !== index));
    toast.success("Image removed");
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="container mx-auto px-4 py-8 max-w-3xl">
        <Link to="/">
          <Button variant="ghost" className="mb-6 gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to listings
          </Button>
        </Link>

        <Card>
          <CardHeader>
            <CardTitle className="text-3xl">Add New Apartment</CardTitle>
            <p className="text-muted-foreground">
              Fill in the details to create a new listing
            </p>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="title">Title *</Label>
                <Input
                  id="title"
                  required
                  placeholder="e.g., Modern Downtown Loft"
                  value={formData.title}
                  onChange={(e) => handleChange("title", e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="address">Address *</Label>
                <Input
                  id="address"
                  required
                  placeholder="e.g., 123 Main Street, Downtown"
                  value={formData.address}
                  onChange={(e) => handleChange("address", e.target.value)}
                />
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="price">Monthly Rent ($) *</Label>
                  <Input
                    id="price"
                    type="number"
                    required
                    placeholder="e.g.,2500"
                    value={formData.price}
                    onChange={(e) => handleChange("price", e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="area">Area (sqft) *</Label>
                  <Input
                    id="area"
                    type="number"
                    required
                    placeholder="e.g., 1200"
                    value={formData.area}
                    onChange={(e) => handleChange("area", e.target.value)}
                  />
                </div>
              </div>

              <div className="grid sm:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="floor">Floor *</Label>
                  <Input
                    id="floor"
                    type="number"
                    required
                    placeholder="e.g., 5"
                    value={formData.floor}
                    onChange={(e) => handleChange("floor", e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="bedrooms">Bedrooms *</Label>
                  <Input
                    id="bedrooms"
                    type="number"
                    required
                    placeholder="e.g., 2"
                    value={formData.bedrooms}
                    onChange={(e) => handleChange("bedrooms", e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="bathrooms">Bathrooms *</Label>
                  <Input
                    id="bathrooms"
                    type="number"
                    step="0.5"
                    required
                    placeholder="e.g., 2"
                    value={formData.bathrooms}
                    onChange={(e) => handleChange("bathrooms", e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description *</Label>
                <Textarea
                  id="description"
                  required
                  placeholder="Describe the apartment..."
                  className="min-h-32"
                  value={formData.description}
                  onChange={(e) => handleChange("description", e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="amenities">Amenities</Label>
                <Input
                  id="amenities"
                  placeholder="e.g., Parking, Gym, Pool (comma separated)"
                  value={formData.amenities}
                  onChange={(e) => handleChange("amenities", e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="noisy">Noise *</Label>
                <Select
                  value={formData.noisy}
                  onValueChange={(value: NoisyLevel) =>
                    handleChange("noisy", value)
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

              <div className="space-y-2">
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
                        !formData.availableFrom && "text-muted-foreground"
                      )}
                    >
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      {formData.availableFrom ? (
                        format(formData.availableFrom, "PPP")
                      ) : (
                        <span>Not available</span>
                      )}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0" align="start">
                    <Calendar
                      mode="single"
                      selected={formData.availableFrom}
                      onSelect={(date) => handleChange("availableFrom", date)}
                      initialFocus
                      className="pointer-events-auto"
                    />
                  </PopoverContent>
                </Popover>
                {formData.availableFrom && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => handleChange("availableFrom", undefined)}
                    className="mt-1"
                  >
                    Clear date
                  </Button>
                )}
              </div>

              <div className="space-y-2">
                <Label>Images *</Label>
                <input
                  type="file"
                  id="image-upload"
                  accept="image/jpeg, image/webp, image/jpg" // Restrict to common, small image types
                  multiple
                  onChange={handleImageUpload}
                  className="hidden"
                />
                <label
                  htmlFor="image-upload"
                  className="border-2 border-dashed rounded-lg p-8 text-center hover:border-primary transition-colors cursor-pointer block"
                >
                  <Upload className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">
                    Click to upload images or drag and drop
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    PNG, JPG up to 10MB
                  </p>
                </label>

                {base64Images.length > 0 && (
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mt-4">
                    {base64Images.map((image, index) => (
                      <div key={index} className="relative group">
                        <img
                          src={image}
                          alt={`Preview ${index + 1}`}
                          className="w-full h-32 object-cover rounded-lg"
                        />
                        <button
                          type="button"
                          onClick={() => handleImageDelete(index)}
                          className="absolute top-2 right-2 p-1 bg-destructive text-destructive-foreground rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  type="submit"
                  className="flex-1"
                  size="lg"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? "Creating..." : "Create Listing"}
                </Button>
                <Link to="/" className="flex-1">
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    size="lg"
                    disabled={isSubmitting}
                  >
                    Cancel
                  </Button>
                </Link>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default AddApartment;
