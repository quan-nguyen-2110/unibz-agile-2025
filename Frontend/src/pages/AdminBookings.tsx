import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Navbar } from "@/components/Navbar";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Calendar,
  MapPin,
  Users,
  CheckCircle,
  XCircle,
  Loader2,
  User,
  Phone,
  Mail,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import {
  BookingFilterSection,
  BookingFilterState,
} from "@/components/BookingFilterSection";
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
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";

import { Booking } from "@/types/booking";
import axios from "axios";

const API_BOOKING_URL =
  (import.meta.env.VITE_BOOKING_API_URL || "https://localhost:7221") +
  "/api/Bookings";

const AdminBookings = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [filteredBookings, setFilteredBookings] = useState<Booking[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [cancelReason, setCancelReason] = useState("");
  const [selectedBookingId, setSelectedBookingId] = useState<string>("");
  const isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
  const userRole = localStorage.getItem("userRole");

  useEffect(() => {
    if (!isLoggedIn || userRole !== "admin") {
      navigate("/");
      return;
    }

    const fetchBookings = async () => {
      setIsLoading(true);
      try {
        const response = await axios.get<Booking[]>(`${API_BOOKING_URL}`);

        setBookings(response.data);
        setFilteredBookings(response.data);
      } catch (err) {
        toast({
          title: "Getting Bookings Failed",
          description: err.message,
          variant: "destructive",
        });
      } finally {
        setIsLoading(false);
      }
    };

    fetchBookings();
  }, [isLoggedIn, userRole, navigate, toast]);

  const handleFilterChange = (filters: BookingFilterState) => {
    let filtered = [...bookings];

    // Filter by status
    if (filters.status !== "all") {
      filtered = filtered.filter(
        (booking) => booking.status === filters.status
      );
    }

    // Filter by apartment name
    if (filters.apartmentName.trim()) {
      filtered = filtered.filter((booking) =>
        booking.apartmentTitle
          .toLowerCase()
          .includes(filters.apartmentName.toLowerCase())
      );
    }

    // Filter by date from (start of day)
    if (filters.dateFrom) {
      const fromDate = new Date(filters.dateFrom);
      fromDate.setHours(0, 0, 0, 0);
      filtered = filtered.filter((booking) => {
        const checkInDate = new Date(booking.checkIn);
        checkInDate.setHours(0, 0, 0, 0);
        return checkInDate >= fromDate;
      });
    }

    // Filter by date to (end of day)
    if (filters.dateTo) {
      const toDate = new Date(filters.dateTo);
      toDate.setHours(23, 59, 59, 999);
      filtered = filtered.filter((booking) => {
        const checkInDate = new Date(booking.checkIn);
        return checkInDate <= toDate;
      });
    }

    setFilteredBookings(filtered);
  };

  const handleConfirmBooking = async (bookingId: string) => {
    setIsLoading(true);
    try {
      const response = await axios.post(
        `${API_BOOKING_URL}/{${bookingId}}/confirm`
      );
      console.log("Success:", response.data);

      const updatedBookings = bookings.map((booking) =>
        booking.id === bookingId
          ? { ...booking, status: "confirmed" as const }
          : booking
      );
      setBookings(updatedBookings);
      setFilteredBookings(updatedBookings);
      // localStorage.setItem("bookings", JSON.stringify(updatedBookings));

      toast({
        title: "Booking Confirmed",
        description: "The booking has been confirmed successfully.",
      });
    } catch (err) {
      toast({
        title: "Confirming Booking Failed",
        description: err.message,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancelBooking = async () => {
    if (!cancelReason.trim()) {
      toast({
        title: "Comment Required",
        description: "Please provide a reason for cancellation.",
        variant: "destructive",
      });
      return;
    }

    try {
      const response = await axios.post(
        `${API_BOOKING_URL}/{${selectedBookingId}}/cancel`,
        { CancelReason: cancelReason }
      );
      console.log("Success:", response.data);

      const updatedBookings = bookings.map((booking) =>
        booking.id === selectedBookingId
          ? {
              ...booking,
              status: "cancelled" as const,
              cancelReason: cancelReason.trim(),
            }
          : booking
      );

      setBookings(updatedBookings);
      setFilteredBookings(updatedBookings);
      // localStorage.setItem("bookings", JSON.stringify(updatedBookings));

      setCancelReason("");
      setSelectedBookingId("");

      toast({
        title: "Booking Cancelled",
        description: "The booking has been cancelled with your comment.",
      });
    } catch (err) {
      toast({
        title: "Cancelling Booking Failed",
        description: err.message,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "confirmed":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300";
      case "cancelled":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300";
      default:
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300";
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">All Bookings</h1>
          <p className="text-muted-foreground">
            Manage all apartment bookings from users
          </p>
        </div>

        <BookingFilterSection onFilterChange={handleFilterChange} />

        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-16">
            <Loader2 className="h-12 w-12 text-primary animate-spin mb-4" />
            <p className="text-muted-foreground">Loading bookings...</p>
          </div>
        ) : filteredBookings.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-16">
              <Calendar className="h-16 w-16 text-muted-foreground mb-4" />
              <h3 className="text-xl font-semibold mb-2">No bookings found</h3>
              <p className="text-muted-foreground">
                {bookings.length === 0
                  ? "No users have made bookings yet."
                  : "No bookings match your filters."}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-6">
            {filteredBookings.map((booking) => (
              <Card key={booking.id} className="overflow-hidden">
                <div className="md:flex">
                  <div className="md:w-1/3">
                    <img
                      src={booking.apartmentImage}
                      alt={booking.apartmentTitle}
                      className="w-full h-64 md:h-full object-cover cursor-pointer hover:opacity-90 transition-opacity"
                      onClick={() =>
                        navigate(`/apartment/${booking.apartmentId}`)
                      }
                    />
                  </div>
                  <div className="md:w-2/3 p-6">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3
                          className="text-2xl font-bold mb-2 cursor-pointer hover:text-primary transition-colors"
                          onClick={() =>
                            navigate(`/apartment/${booking.apartmentId}`)
                          }
                        >
                          {booking.apartmentTitle}
                        </h3>
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <MapPin className="h-4 w-4" />
                          <span>{booking.apartmentAddress}</span>
                        </div>
                      </div>
                      <Badge className={getStatusColor(booking.status)}>
                        {booking.status.charAt(0).toUpperCase() +
                          booking.status.slice(1)}
                      </Badge>
                    </div>

                    <div className="flex items-center gap-2 text-muted-foreground mt-1 mb-4">
                      <User className="h-4 w-4" />
                      <span>
                        Booked by:{" "}
                        <span className="font-medium text-foreground">
                          {booking.userName || "Unknown User"}
                        </span>
                      </span>

                      <span className="text-muted-foreground/50">•</span>

                      <Phone className="h-4 w-4" />
                      <span className="font-medium text-foreground">
                        {booking.userPhone || "Unknown Phone"}
                      </span>

                      <span className="text-muted-foreground/50">•</span>

                      <Mail className="h-4 w-4" />
                      <span className="font-medium text-foreground">
                        {booking.userEmail || "Unknown Email"}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                      <div className="flex items-center gap-2">
                        <Calendar className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Check-in
                          </p>
                          <p className="font-semibold">
                            {formatDate(booking.checkIn)}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Calendar className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Check-out
                          </p>
                          <p className="font-semibold">
                            {formatDate(booking.checkOut)}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Users className="h-5 w-5 text-primary" />
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Guests
                          </p>
                          <p className="font-semibold">{booking.guests}</p>
                        </div>
                      </div>
                    </div>

                    {booking.cancelReason && (
                      <div className="mb-4 p-3 bg-muted rounded-lg">
                        <p className="text-sm font-semibold text-muted-foreground mb-1">
                          Cancellation Reason:
                        </p>
                        <p className="text-sm">{booking.cancelReason}</p>
                      </div>
                    )}

                    <div className="border-t pt-4 flex justify-between items-center">
                      <div>
                        <p className="text-sm text-muted-foreground">
                          Total Cost
                        </p>
                        <p className="text-2xl font-bold text-primary">
                          ${booking.totalPrice.toLocaleString()}
                          <span className="text-sm text-muted-foreground ml-2">
                            ({booking.nights} night
                            {booking.nights > 1 ? "s" : ""})
                          </span>
                        </p>
                      </div>
                      <div className="flex gap-2">
                        {booking.status === "pending" && (
                          <>
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="default">
                                  <CheckCircle className="h-4 w-4 mr-2" />
                                  Confirm
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>
                                    Confirm this booking?
                                  </AlertDialogTitle>
                                  <AlertDialogDescription>
                                    Are you sure you want to confirm this
                                    booking for {booking.apartmentTitle}? The
                                    user will be notified of the confirmation.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() =>
                                      handleConfirmBooking(booking.id)
                                    }
                                  >
                                    Confirm Booking
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="destructive"
                                  onClick={() =>
                                    setSelectedBookingId(booking.id)
                                  }
                                >
                                  <XCircle className="h-4 w-4 mr-2" />
                                  Cancel with Comment
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>
                                    Cancel this booking?
                                  </AlertDialogTitle>
                                  <AlertDialogDescription>
                                    Please provide a reason for cancelling this
                                    booking. The user will see this comment.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <div className="py-4">
                                  <Label htmlFor="cancelReason">
                                    Cancellation Reason
                                  </Label>
                                  <Textarea
                                    id="cancelReason"
                                    placeholder="e.g., Property maintenance scheduled, double booking, etc."
                                    value={cancelReason}
                                    onChange={(e) =>
                                      setCancelReason(e.target.value)
                                    }
                                    className="mt-2"
                                    rows={4}
                                  />
                                </div>
                                <AlertDialogFooter>
                                  <AlertDialogCancel
                                    onClick={() => {
                                      setCancelReason("");
                                      setSelectedBookingId("");
                                    }}
                                  >
                                    Keep Booking
                                  </AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={handleCancelBooking}
                                  >
                                    Cancel Booking
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminBookings;
