import React, { useState, useEffect } from "react";
import { api } from "../App";
import { Trophy, Medal } from "lucide-react";

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

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        <div className="mb-8">
          <div className="flex items-center space-x-3 mb-2">
            <Trophy className="text-yellow-400" size={32} />
            <h1 className="text-4xl font-bold text-white">
              Global Leaderboard
            </h1>
          </div>
          <p className="text-gray-400">
            Top performers in the OWASP Labs Platform
          </p>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4"></div>
            <p className="text-gray-300">Loading leaderboard...</p>
          </div>
        ) : (
          <div className="space-y-3">
            {leaderboard.map((user, index) => (
              <div
                key={user.id}
                className={`bg-gray-800 border rounded-lg p-4 transition-all ${
                  index < 3
                    ? "border-yellow-700 shadow-lg shadow-yellow-500/20"
                    : "border-gray-700"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="text-3xl font-bold w-12 text-center">
                      {getMedalIcon(index + 1)}
                    </div>
                    <div>
                      <p className="text-lg font-bold text-white">
                        {user.username}
                      </p>
                      <p className="text-gray-400 text-sm">
                        Completed {user.labs_completed} labs
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-2xl font-bold text-yellow-400">
                      {user.total_points} XP
                    </p>
                    <p className="text-gray-400 text-sm">
                      {new Date(user.last_completed).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {leaderboard.length === 0 && !loading && (
          <div className="text-center py-12">
            <p className="text-gray-400 text-lg">
              No users on the leaderboard yet.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LeaderboardPage;
