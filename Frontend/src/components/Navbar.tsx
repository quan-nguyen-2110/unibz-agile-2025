import { Link, useLocation } from "react-router-dom";
import { Home, PlusCircle, User, LogIn, Calendar } from "lucide-react";
import { Button } from "./ui/button";

export const Navbar = () => {
  const location = useLocation();
  const isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
  const userRole = localStorage.getItem("userRole");
  
  // Hide navigation buttons on auth pages
  const isAuthPage = ['/login', '/register', '/forgot-password', '/reset-password'].includes(location.pathname);

  return (
    <nav className="border-b bg-card shadow-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 text-2xl font-bold text-primary">
          <Home className="h-7 w-7" />
          <span>RentHub</span>
        </Link>
        
        <div className="flex items-center gap-3">
          {!isAuthPage && (
            <>
              <Link to="/">
                <Button variant="ghost">Browse</Button>
              </Link>
              {isLoggedIn && userRole === "user" && (
                <Link to="/bookings">
                  <Button variant="ghost" className="gap-2">
                    <Calendar className="h-4 w-4" />
                    My Bookings
                  </Button>
                </Link>
              )}
              {userRole === "admin" && (
                <>
                  <Link to="/add">
                    <Button variant="default" className="gap-2">
                      <PlusCircle className="h-4 w-4" />
                      Add Apartment
                    </Button>
                  </Link>
                  <Link to="/admin/bookings">
                    <Button variant="ghost" className="gap-2">
                      <Calendar className="h-4 w-4" />
                      All Bookings
                    </Button>
                  </Link>
                </>
              )}
              {isLoggedIn ? (
                <Link to="/profile">
                  <Button variant="outline" className="gap-2">
                    <User className="h-4 w-4" />
                    Profile
                  </Button>
                </Link>
              ) : (
                <Link to="/login">
                  <Button variant="outline" className="gap-2">
                    <LogIn className="h-4 w-4" />
                    Login
                  </Button>
                </Link>
              )}
            </>
          )}
        </div>
      </div>
    </nav>
  );
};
