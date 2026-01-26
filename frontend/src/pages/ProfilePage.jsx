import React, { useState, useEffect } from "react";
import { User, Mail, Calendar, Award, Flame, Target } from "lucide-react";
import api from "../utils/api";

const ProfilePage = ({ user: initialUser }) => {
  const [user, setUser] = useState(initialUser);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(!initialUser);

  useEffect(() => {
    if (!initialUser) {
      fetchUserProfile();
    }
    fetchUserStats();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const response = await api.get("/api/user/profile");
      setUser(response.data);
    } catch (error) {
      console.error("Failed to fetch user profile:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserStats = async () => {
    try {
      const response = await api.get("/api/user/progress");
      setStats(response.data);
    } catch (error) {
      console.error("Failed to fetch stats:", error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-400 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-slate-300">Loading profile...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 py-12">
      <div className="max-w-4xl mx-auto px-4">
        {/* Profile Header */}
        <div className="backdrop-blur-xl bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl p-8 mb-8">
          <div className="flex items-start justify-between mb-8">
            <div className="flex items-center space-x-6">
              <div className="w-24 h-24 bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 rounded-2xl flex items-center justify-center shadow-xl shadow-cyan-500/30">
                <User size={48} className="text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 mb-2">
                  {user?.username}
                </h1>
                <p className="text-slate-400 text-sm capitalize font-medium">
                  {user?.role} Account
                </p>
              </div>
            </div>
          </div>

          {/* User Info Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="flex items-center space-x-4 p-4 bg-slate-700/30 rounded-lg border border-slate-600/30">
              <div className="p-3 bg-cyan-500/20 rounded-lg">
                <Mail className="text-cyan-400" size={24} />
              </div>
              <div>
                <p className="text-slate-400 text-sm font-medium">Email</p>
                <p className="text-white font-medium">{user?.email || "N/A"}</p>
              </div>
            </div>

            <div className="flex items-center space-x-4 p-4 bg-slate-700/30 rounded-lg border border-slate-600/30">
              <div className="p-3 bg-purple-500/20 rounded-lg">
                <Calendar className="text-purple-400" size={24} />
              </div>
              <div>
                <p className="text-slate-400 text-sm font-medium">Joined</p>
                <p className="text-white font-medium">
                  {user?.created_at
                    ? new Date(user.created_at).toLocaleDateString()
                    : "N/A"}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Section */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Labs Completed */}
            <div className="backdrop-blur-xl bg-gradient-to-br from-emerald-500/10 to-green-600/10 border border-emerald-500/30 rounded-xl p-6 hover:border-emerald-400/50 transition-all">
              <div className="flex items-center space-x-4 mb-4">
                <div className="p-3 bg-emerald-500/20 rounded-lg">
                  <Target className="text-emerald-400" size={28} />
                </div>
                <div>
                  <p className="text-slate-400 text-sm font-medium">
                    Labs Completed
                  </p>
                  <p className="text-4xl font-black text-emerald-300 mt-1">
                    {stats.completed_labs}/{stats.total_labs}
                  </p>
                </div>
              </div>
              <div className="w-full bg-slate-700/30 rounded-full h-2 mt-4 overflow-hidden">
                <div
                  className="bg-gradient-to-r from-emerald-400 to-green-500 h-full transition-all duration-500"
                  style={{
                    width: `${
                      stats.total_labs > 0
                        ? (stats.completed_labs / stats.total_labs) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>

            {/* Total Points */}
            <div className="backdrop-blur-xl bg-gradient-to-br from-yellow-500/10 to-amber-600/10 border border-yellow-500/30 rounded-xl p-6 hover:border-yellow-400/50 transition-all">
              <div className="flex items-center space-x-4 mb-4">
                <div className="p-3 bg-yellow-500/20 rounded-lg">
                  <Award className="text-yellow-400" size={28} />
                </div>
                <div>
                  <p className="text-slate-400 text-sm font-medium">
                    Total Points
                  </p>
                  <p className="text-4xl font-black text-yellow-300 mt-1">
                    {stats.total_points}
                  </p>
                </div>
              </div>
              <p className="text-yellow-300/70 text-sm mt-4">
                Earned through completed challenges
              </p>
            </div>

            {/* Completion Rate */}
            <div className="backdrop-blur-xl bg-gradient-to-br from-orange-500/10 to-red-600/10 border border-orange-500/30 rounded-xl p-6 hover:border-orange-400/50 transition-all">
              <div className="flex items-center space-x-4 mb-4">
                <div className="p-3 bg-orange-500/20 rounded-lg">
                  <Flame className="text-orange-400" size={28} />
                </div>
                <div>
                  <p className="text-slate-400 text-sm font-medium">
                    Completion Rate
                  </p>
                  <p className="text-4xl font-black text-orange-300 mt-1">
                    {stats.total_labs > 0
                      ? Math.round(
                          (stats.completed_labs / stats.total_labs) * 100,
                        )
                      : 0}
                    %
                  </p>
                </div>
              </div>
              <p className="text-orange-300/70 text-sm mt-4">
                Of all available labs
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProfilePage;
