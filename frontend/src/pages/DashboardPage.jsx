import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Zap, Trophy, Target, Search, Play, AlertCircle } from "lucide-react";
import api from "../utils/api";

const DashboardPage = () => {
  const [labs, setLabs] = useState([]);
  const [filteredLabs, setFilteredLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [difficultyFilter, setDifficultyFilter] = useState("all");
  const [progress, setProgress] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchLabs();
    fetchProgress();
  }, []);

  useEffect(() => {
    filterLabs();
  }, [labs, searchTerm, categoryFilter, difficultyFilter]);

  const fetchLabs = async () => {
    try {
      setError("");
      const response = await api.get("/api/labs");
      setLabs(response.data || []);
    } catch (err) {
      setError("Failed to load labs");
      setLabs([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchProgress = async () => {
    try {
      const response = await api.get("/api/user/progress");
      setProgress(response.data);
    } catch (err) {
      console.error("Failed to fetch progress:", err);
    }
  };

  const filterLabs = () => {
    let filtered = labs;

    if (searchTerm) {
      filtered = filtered.filter(
        (lab) =>
          lab.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          lab.description?.toLowerCase().includes(searchTerm.toLowerCase()),
      );
    }

    if (categoryFilter !== "all") {
      filtered = filtered.filter((lab) => lab.category === categoryFilter);
    }

    if (difficultyFilter !== "all") {
      const [min, max] = difficultyFilter.split("-").map(Number);
      filtered = filtered.filter(
        (lab) => lab.difficulty >= min && lab.difficulty <= max,
      );
    }

    setFilteredLabs(filtered);
  };

  const categories = [
    "sql_injection",
    "ssrf",
    "csrf",
    "xss",
    "xxe",
    "idor",
    "rce",
    "command_injection",
  ];

  const getDifficultyColor = (difficulty) => {
    if (difficulty <= 5)
      return "bg-gradient-to-r from-emerald-500/20 to-green-600/20 text-emerald-300 border-emerald-500/50";
    if (difficulty <= 10)
      return "bg-gradient-to-r from-yellow-500/20 to-amber-600/20 text-yellow-300 border-yellow-500/50";
    if (difficulty <= 15)
      return "bg-gradient-to-r from-orange-500/20 to-red-600/20 text-orange-300 border-orange-500/50";
    return "bg-gradient-to-r from-red-500/20 to-rose-600/20 text-red-300 border-red-500/50";
  };

  const getDifficultyLabel = (difficulty) => {
    if (difficulty <= 5) return "Beginner";
    if (difficulty <= 10) return "Intermediate";
    if (difficulty <= 15) return "Advanced";
    return "Master";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 py-8">
      <div className="max-w-7xl mx-auto px-4">
        {/* Header Section */}
        <div className="mb-12">
          <div className="flex items-center space-x-3 mb-4">
            <Target className="text-cyan-400" size={32} />
            <div>
              <h1 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
                Security Labs
              </h1>
              <p className="text-slate-400 text-sm mt-1">
                Master real-world cybersecurity challenges
              </p>
            </div>
          </div>

          {/* Stats Cards */}
          {progress && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
              <div className="backdrop-blur-xl bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-cyan-500/30 rounded-xl p-5 hover:border-cyan-400/50 transition-all">
                <div className="flex items-center space-x-3">
                  <div className="p-3 bg-cyan-500/20 rounded-lg">
                    <Zap className="text-cyan-400" size={24} />
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Labs Completed</p>
                    <p className="text-3xl font-bold text-cyan-300">
                      {progress.completed_labs}/{progress.total_labs}
                    </p>
                  </div>
                </div>
              </div>

              <div className="backdrop-blur-xl bg-gradient-to-br from-yellow-500/10 to-amber-600/10 border border-yellow-500/30 rounded-xl p-5 hover:border-yellow-400/50 transition-all">
                <div className="flex items-center space-x-3">
                  <div className="p-3 bg-yellow-500/20 rounded-lg">
                    <Trophy className="text-yellow-400" size={24} />
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Total Points</p>
                    <p className="text-3xl font-bold text-yellow-300">
                      {progress.total_points} XP
                    </p>
                  </div>
                </div>
              </div>

              <div className="backdrop-blur-xl bg-gradient-to-br from-purple-500/10 to-pink-600/10 border border-purple-500/30 rounded-xl p-5 hover:border-purple-400/50 transition-all">
                <div className="flex items-center space-x-3">
                  <div className="p-3 bg-purple-500/20 rounded-lg">
                    <Target className="text-purple-400" size={24} />
                  </div>
                  <div>
                    <p className="text-slate-400 text-sm">Completion Rate</p>
                    <p className="text-3xl font-bold text-purple-300">
                      {progress.total_labs > 0
                        ? Math.round(
                            (progress.completed_labs / progress.total_labs) *
                              100,
                          )
                        : 0}
                      %
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/50 rounded-xl flex items-start space-x-3 animate-pulse">
            <AlertCircle
              className="text-red-400 flex-shrink-0 mt-0.5"
              size={20}
            />
            <div>
              <p className="text-red-200 font-semibold">Error</p>
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Filters Section */}
        <div className="backdrop-blur-xl bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search
                className="absolute left-4 top-3.5 text-slate-400"
                size={20}
              />
              <input
                type="text"
                placeholder="Search labs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-12 pr-4 py-2.5 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all"
              />
            </div>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-4 py-2.5 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all"
            >
              <option value="all">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat.replace("_", " ").toUpperCase()}
                </option>
              ))}
            </select>

            {/* Difficulty Filter */}
            <select
              value={difficultyFilter}
              onChange={(e) => setDifficultyFilter(e.target.value)}
              className="px-4 py-2.5 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all"
            >
              <option value="all">All Difficulties</option>
              <option value="1-5">Beginner</option>
              <option value="6-10">Intermediate</option>
              <option value="11-15">Advanced</option>
              <option value="16-20">Master</option>
            </select>
          </div>
        </div>

        {/* Loading State */}
        {loading ? (
          <div className="text-center py-16">
            <div className="inline-block p-4 bg-gradient-to-r from-cyan-500/20 to-blue-600/20 rounded-full mb-4 animate-pulse">
              <div className="animate-spin h-12 w-12 border-4 border-cyan-400 border-t-transparent rounded-full"></div>
            </div>
            <p className="text-slate-300 font-medium">Loading labs...</p>
          </div>
        ) : (
          <>
            {/* Labs Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredLabs.map((lab) => (
                <div
                  key={lab.id}
                  className="group backdrop-blur-xl bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-xl hover:border-cyan-400/50 transition-all duration-300 hover:shadow-xl hover:shadow-cyan-500/10 overflow-hidden"
                >
                  <div className="p-6">
                    {/* Category & Difficulty */}
                    <div className="flex items-center justify-between mb-4">
                      <span className="px-3 py-1 bg-blue-500/20 text-blue-300 text-xs font-bold rounded-full border border-blue-500/30">
                        {lab.category?.replace("_", " ").toUpperCase()}
                      </span>
                      <span
                        className={`px-3 py-1 text-xs font-bold rounded-full border ${getDifficultyColor(
                          lab.difficulty || 1,
                        )}`}
                      >
                        {getDifficultyLabel(lab.difficulty || 1)}
                      </span>
                    </div>

                    {/* Title */}
                    <h3 className="text-lg font-bold text-white mb-2 group-hover:text-cyan-400 transition">
                      {lab.title}
                    </h3>

                    {/* Description */}
                    <p className="text-slate-400 text-sm mb-4 line-clamp-2 min-h-10">
                      {lab.description}
                    </p>

                    {/* Footer */}
                    <div className="flex items-center justify-between pt-4 border-t border-slate-700/50">
                      <span className="text-yellow-400 font-bold text-sm">
                        +{lab.points || 100} XP
                      </span>
                      <button
                        onClick={() => navigate(`/lab/${lab.id}`)}
                        className="flex items-center space-x-1 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white px-4 py-2 rounded-lg transition-all duration-200 font-medium shadow-lg shadow-cyan-500/25"
                      >
                        <Play size={16} />
                        <span>Start</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Empty State */}
            {filteredLabs.length === 0 && !loading && !error && (
              <div className="text-center py-16">
                <div className="text-6xl mb-4">🔍</div>
                <p className="text-slate-400 text-lg">
                  No labs found matching your filters.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;
