import React from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { LogOut, Home, Trophy, User, Shield } from "lucide-react";

const Navigation = ({ user, onLogout }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    onLogout();
    navigate("/login");
  };

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="backdrop-blur-xl bg-gradient-to-r from-slate-900 to-slate-800 border-b border-slate-700/50 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <Link to="/dashboard" className="flex items-center space-x-3 group">
            <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-xl group-hover:shadow-lg group-hover:shadow-cyan-500/50 transition-all">
              <Shield size={24} className="text-white" />
            </div>
            <div>
              <div className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
                OWASP Labs
              </div>
              <p className="text-xs text-slate-400">Security Training</p>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <Link
              to="/dashboard"
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 ${
                isActive("/dashboard")
                  ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/50"
                  : "text-slate-400 hover:text-cyan-400 hover:bg-slate-700/50"
              }`}
            >
              <Home size={20} />
              <span className="font-medium">Labs</span>
            </Link>
            <Link
              to="/leaderboard"
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 ${
                isActive("/leaderboard")
                  ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/50"
                  : "text-slate-400 hover:text-yellow-400 hover:bg-slate-700/50"
              }`}
            >
              <Trophy size={20} />
              <span className="font-medium">Leaderboard</span>
            </Link>
          </div>

          {/* User Menu */}
          <div className="flex items-center space-x-4">
            <Link
              to="/profile"
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 ${
                isActive("/profile")
                  ? "bg-purple-500/20 text-purple-400 border border-purple-500/50"
                  : "text-slate-400 hover:text-purple-400 hover:bg-slate-700/50"
              }`}
            >
              <User size={20} />
              <span className="hidden sm:inline font-medium">{user?.username || "User"}</span>
            </Link>
            <button
              onClick={handleLogout}
              className="flex items-center space-x-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 hover:text-red-300 border border-red-600/50 hover:border-red-500 px-4 py-2 rounded-lg transition-all duration-200 font-medium"
            >
              <LogOut size={20} />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
