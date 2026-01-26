import React, { useState, useEffect } from "react";
import { Trophy, Zap, TrendingUp } from "lucide-react";
import api from "../utils/api";

const LeaderboardPage = () => {
  const [leaderboard, setLeaderboard] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLeaderboard();
  }, []);

  const fetchLeaderboard = async () => {
    try {
      const response = await api.get("/api/leaderboard?limit=100");
      setLeaderboard(response.data);
    } catch (error) {
      console.error("Failed to fetch leaderboard:", error);
    } finally {
      setLoading(false);
    }
  };

  const getMedalIcon = (rank) => {
    if (rank === 1) return "🥇";
    if (rank === 2) return "🥈";
    if (rank === 3) return "🥉";
    return `${rank}.`;
  };

  const getRankColor = (rank) => {
    if (rank === 1)
      return "from-yellow-500/20 to-amber-600/20 border-yellow-500/30";
    if (rank === 2)
      return "from-gray-400/20 to-slate-500/20 border-gray-400/30";
    if (rank === 3)
      return "from-orange-500/20 to-amber-600/20 border-orange-500/30";
    return "from-slate-800/50 to-slate-900/50 border-slate-700/50";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 py-12">
      <div className="max-w-5xl mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-block mb-4">
            <Trophy className="text-yellow-400 animate-bounce" size={40} />
          </div>
          <h1 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-yellow-400 via-orange-400 to-red-400 mb-3">
            Global Leaderboard
          </h1>
          <p className="text-slate-400 text-lg">
            Top performers in the OWASP Labs Platform
          </p>
        </div>

        {/* Loading State */}
        {loading ? (
          <div className="text-center py-16">
            <div className="inline-block p-4 bg-gradient-to-r from-cyan-500/20 to-blue-600/20 rounded-full mb-4 animate-pulse">
              <div className="animate-spin h-12 w-12 border-4 border-cyan-400 border-t-transparent rounded-full"></div>
            </div>
            <p className="text-slate-300 font-medium">Loading leaderboard...</p>
          </div>
        ) : (
          <div className="space-y-3">
            {leaderboard.map((user, index) => (
              <div
                key={user.id}
                className={`backdrop-blur-xl bg-gradient-to-r ${getRankColor(
                  index + 1,
                )} border rounded-xl p-6 transition-all hover:shadow-xl hover:shadow-cyan-500/10 transform hover:scale-105 hover:-translate-y-1 duration-300`}
              >
                <div className="flex items-center justify-between">
                  {/* Rank & User Info */}
                  <div className="flex items-center space-x-4">
                    {/* Medal */}
                    <div
                      className={`text-4xl font-black w-16 text-center ${
                        index < 3 ? "animate-pulse" : ""
                      }`}
                    >
                      {getMedalIcon(index + 1)}
                    </div>

                    {/* User Details */}
                    <div>
                      <p className="text-xl font-bold text-white mb-1">
                        {user.username}
                        {index < 3 && (
                          <span className="ml-2 text-sm">
                            {index === 0 && "👑"}
                            {index === 1 && "🌟"}
                            {index === 2 && "⭐"}
                          </span>
                        )}
                      </p>
                      <div className="flex items-center space-x-3 text-sm text-slate-400">
                        <div className="flex items-center space-x-1">
                          <Zap size={16} className="text-cyan-400" />
                          <span>{user.labs_completed} labs completed</span>
                        </div>
                        {user.last_completed && (
                          <div className="flex items-center space-x-1">
                            <span>•</span>
                            <span>
                              {new Date(
                                user.last_completed,
                              ).toLocaleDateString()}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Points */}
                  <div className="text-right">
                    <div className="flex items-center space-x-2 justify-end mb-2">
                      <TrendingUp className="text-yellow-400" size={20} />
                      <p className="text-3xl font-black text-yellow-300">
                        {user.total_points}
                      </p>
                    </div>
                    <p className="text-sm text-slate-400">XP Earned</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Empty State */}
        {leaderboard.length === 0 && !loading && (
          <div className="text-center py-16">
            <div className="text-6xl mb-4">📊</div>
            <p className="text-slate-400 text-lg">
              No users on the leaderboard yet.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LeaderboardPage;
