import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { LogOut, Home, Trophy, User } from "lucide-react";

const Navigation = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    onLogout();
    navigate("/login");
  };

  return (
    <nav className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <Link to="/dashboard" className="flex items-center space-x-2">
            <div className="text-2xl font-bold text-cyan-400">
              🛡️ OWASP Labs
            </div>
          </Link>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center space-x-8">
            <Link
              to="/dashboard"
              className="flex items-center space-x-2 hover:text-cyan-400 transition"
            >
              <Home size={20} />
              <span>Labs</span>
            </Link>
            <Link
              to="/leaderboard"
              className="flex items-center space-x-2 hover:text-cyan-400 transition"
            >
              <Trophy size={20} />
              <span>Leaderboard</span>
            </Link>
          </div>

          {/* User Menu */}
          <div className="flex items-center space-x-4">
            <Link
              to="/profile"
              className="flex items-center space-x-2 hover:text-cyan-400 transition"
            >
              <User size={20} />
              <span className="hidden sm:inline">
                {user?.username || "User"}
              </span>
            </Link>
            <button
              onClick={handleLogout}
              className="flex items-center space-x-2 bg-red-600 hover:bg-red-700 px-4 py-2 rounded transition"
            >
              <LogOut size={20} />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
