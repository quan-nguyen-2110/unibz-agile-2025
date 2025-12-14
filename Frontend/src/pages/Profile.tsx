import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useToast } from "@/hooks/use-toast";
import { Navbar } from "@/components/Navbar";
import { User, Mail, LogOut, KeyRound, ChevronDown } from "lucide-react";
import axios from "axios";

export default function Profile() {
  const API_USER_URL = (import.meta.env.VITE_USER_API_URL ||
    "http://localhost:5000") as string;
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isPasswordOpen, setIsPasswordOpen] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [profileData, setProfileData] = useState({
    id: "",
    name: "",
    email: "",
    phone: "",
  });
  const [updatedProfileData, setUpdatedProfileData] = useState(profileData);
  const [isAdmin, setIsAdmin] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    const isLoggedIn = localStorage.getItem("isLoggedIn");
    if (!isLoggedIn) {
      navigate("/login");
      return;
    }

    // Load user data from localStorage
    const userId =
      localStorage.getItem("userId") || "00000000-0000-0000-0000-000000000000";
    const userName = localStorage.getItem("userName") || "Regular User";
    setIsAdmin(
      localStorage.getItem("userRole") === "Admin" ||
        localStorage.getItem("userRole") === "admin"
    );
    const userEmail =
      localStorage.getItem("userEmail") || "unknow_user@example.com";
    const phoneNumber = localStorage.getItem("userPhone") || "+1 234 567 8900";
    setProfileData({
      id: userId,
      name: userName,
      email: userEmail,
      phone: phoneNumber,
    });
  }, [navigate]);

  useEffect(() => {
    setUpdatedProfileData(profileData);
  }, [profileData]);

  const handleSave = async () => {
    setIsLoading(true);

    try {
      const response = await axios.post(
        `${API_USER_URL}/api/update-profile`,
        updatedProfileData
      );
      console.log("Success:", response.data);
      if (response.data && response.data.success) {
        setProfileData(updatedProfileData);
        localStorage.setItem("userName", updatedProfileData.name);
        localStorage.setItem("userEmail", updatedProfileData.email);
        localStorage.setItem("userPhone", updatedProfileData.phone);
        setIsEditing(false);
        toast({
          title: "Profile updated",
          description: "Your changes have been saved successfully",
        });
      } else {
        toast({
          title: "Updated Profile Failed",
          description:
            response?.data?.errors[0] ||
            "Please check your inputs and try again",
          variant: "destructive",
        });
      }
    } catch (err) {
      console.error("Error saving profile:", err);
      toast({
        title: "Updated Profile Failed",
        description:
          err?.data?.errors[0] || "Please check your inputs and try again",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordChange = async () => {
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast({
        title: "Error",
        description: "New passwords do not match",
        variant: "destructive",
      });
      return;
    }

    if (passwordData.newPassword.length < 8) {
      toast({
        title: "Error",
        description: "Password must be at least 8 characters",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);
    try {
      const response = await axios.post(`${API_USER_URL}/api/reset-password`, {
        email: profileData.email,
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword,
        newPassword2: passwordData.confirmPassword,
      });
      console.log("Success:", response.data);
      if (response.data.success) {
        setPasswordData({
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        });
        setIsPasswordOpen(false);
        toast({
          title: "Password updated",
          description: "Your password has been changed successfully",
        });
      } else {
        toast({
          title: "Reset password failed",
          description: "Current password is incorrect",
          variant: "destructive",
        });
      }
    } catch (err) {
      toast({
        title: "Reset password failed",
        description: "An error occurred while changing password",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userName");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("userRole");
    localStorage.removeItem("userPhone");
    localStorage.removeItem("userId");
    toast({
      title: "Logged out",
      description: "You have been successfully logged out",
    });
    navigate("/login");
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-2xl mx-auto space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Profile Information
              </CardTitle>
              <CardDescription>
                View and update your personal information
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Full Name</Label>
                <Input
                  id="name"
                  type="text"
                  value={updatedProfileData.name}
                  onChange={(e) =>
                    setUpdatedProfileData({
                      ...updatedProfileData,
                      name: e.target.value,
                    })
                  }
                  disabled={!isEditing}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email" className="flex items-center gap-2">
                  <Mail className="h-4 w-4" />
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={updatedProfileData.email}
                  onChange={(e) =>
                    setUpdatedProfileData({
                      ...updatedProfileData,
                      email: e.target.value,
                    })
                  }
                  disabled={!isEditing}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="phone">Phone Number</Label>
                <Input
                  id="phone"
                  type="tel"
                  value={updatedProfileData.phone}
                  onChange={(e) =>
                    setUpdatedProfileData({
                      ...updatedProfileData,
                      phone: e.target.value,
                    })
                  }
                  disabled={!isEditing}
                />
              </div>
              {!isAdmin && (
                <div className="flex gap-3 pt-4">
                  {!isEditing ? (
                    <Button
                      onClick={() => setIsEditing(true)}
                      className="flex-1"
                    >
                      Edit Profile
                    </Button>
                  ) : (
                    <>
                      <Button
                        onClick={handleSave}
                        disabled={isLoading}
                        className="flex-1"
                      >
                        {isLoading ? "Saving..." : "Save Changes"}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => {
                          setUpdatedProfileData(profileData);
                          setIsEditing(false);
                        }}
                        disabled={isLoading}
                        className="flex-1"
                      >
                        Cancel
                      </Button>
                    </>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {!isAdmin && (
            <Card>
              <Collapsible
                open={isPasswordOpen}
                onOpenChange={setIsPasswordOpen}
              >
                <CardHeader>
                  <CollapsibleTrigger className="flex items-center justify-between w-full hover:opacity-80 transition-opacity">
                    <div className="flex items-center gap-2">
                      <KeyRound className="h-5 w-5" />
                      <CardTitle>Change Password</CardTitle>
                    </div>
                    <ChevronDown
                      className={`h-5 w-5 transition-transform ${
                        isPasswordOpen ? "rotate-180" : ""
                      }`}
                    />
                  </CollapsibleTrigger>
                  <CardDescription>
                    Update your account password
                  </CardDescription>
                </CardHeader>
                <CollapsibleContent>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="currentPassword">Current Password</Label>
                      <Input
                        id="currentPassword"
                        type="password"
                        value={passwordData.currentPassword}
                        onChange={(e) =>
                          setPasswordData({
                            ...passwordData,
                            currentPassword: e.target.value,
                          })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="newPassword">New Password</Label>
                      <Input
                        id="newPassword"
                        type="password"
                        value={passwordData.newPassword}
                        onChange={(e) =>
                          setPasswordData({
                            ...passwordData,
                            newPassword: e.target.value,
                          })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">
                        Confirm New Password
                      </Label>
                      <Input
                        id="confirmPassword"
                        type="password"
                        value={passwordData.confirmPassword}
                        onChange={(e) =>
                          setPasswordData({
                            ...passwordData,
                            confirmPassword: e.target.value,
                          })
                        }
                      />
                    </div>
                    <Button
                      onClick={handlePasswordChange}
                      disabled={
                        isLoading ||
                        !passwordData.currentPassword ||
                        !passwordData.newPassword ||
                        !passwordData.confirmPassword
                      }
                      className="w-full"
                    >
                      {isLoading ? "Updating..." : "Update Password"}
                    </Button>
                  </CardContent>
                </CollapsibleContent>
              </Collapsible>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Account Actions</CardTitle>
              <CardDescription>Manage your account settings</CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                variant="destructive"
                onClick={handleLogout}
                className="w-full gap-2"
              >
                <LogOut className="h-4 w-4" />
                Logout
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
