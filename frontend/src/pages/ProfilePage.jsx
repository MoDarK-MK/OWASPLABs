import React, { useEffect, useState } from "react";
import { api } from "../App";
import { User, Mail, Calendar, Award } from "lucide-react";

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
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-gray-300">Loading profile...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-2xl mx-auto px-4">
        {}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 mb-6">
          <div className="flex items-start justify-between mb-6">
            <div className="flex items-center space-x-4">
              <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-full flex items-center justify-center">
                <User size={32} className="text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white">
                  {user?.username}
                </h1>
                <p className="text-gray-400 text-sm capitalize">
                  {user?.role} Account
                </p>
              </div>
            </div>
          </div>

          {}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center space-x-3">
              <Mail className="text-cyan-400" size={20} />
              <div>
                <p className="text-gray-400 text-sm">Email</p>
                <p className="text-white">{user?.email}</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Calendar className="text-cyan-400" size={20} />
              <div>
                <p className="text-gray-400 text-sm">Joined</p>
                <p className="text-white">
                  {user?.created_at
                    ? new Date(user.created_at).toLocaleDateString()
                    : "N/A"}
                </p>
              </div>
            </div>
          </div>
        </div>

        {}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm mb-1">Labs Completed</p>
                  <p className="text-3xl font-bold text-cyan-400">
                    {stats.completed_labs}
                  </p>
                </div>
                <Award className="text-cyan-400" size={32} />
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm mb-1">Total Points</p>
                  <p className="text-3xl font-bold text-yellow-400">
                    {stats.total_points} XP
                  </p>
                </div>
                <Award className="text-yellow-400" size={32} />
              </div>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <div>
                <p className="text-gray-400 text-sm mb-1">
                  Total Labs Available
                </p>
                <p className="text-3xl font-bold text-green-400">
                  {stats.total_labs}
                </p>
                <p className="text-gray-400 text-sm mt-2">
                  {Math.round((stats.completed_labs / stats.total_labs) * 100)}%
                  Complete
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProfilePage;
