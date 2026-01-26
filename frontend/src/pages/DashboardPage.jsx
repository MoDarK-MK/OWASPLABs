import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../App";
import { Search, Filter, ChevronRight, Play, AlertCircle } from "lucide-react";

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
          lab.description?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (categoryFilter !== "all") {
      filtered = filtered.filter((lab) => lab.category === categoryFilter);
    }

    if (difficultyFilter !== "all") {
      const [min, max] = difficultyFilter.split("-").map(Number);
      filtered = filtered.filter(
        (lab) => lab.difficulty >= min && lab.difficulty <= max
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
      return "bg-green-900/20 text-green-300 border-green-700";
    if (difficulty <= 10)
      return "bg-yellow-900/20 text-yellow-300 border-yellow-700";
    if (difficulty <= 15)
      return "bg-orange-900/20 text-orange-300 border-orange-700";
    return "bg-red-900/20 text-red-300 border-red-700";
  };

  const getDifficultyLabel = (difficulty) => {
    if (difficulty <= 5) return "Beginner";
    if (difficulty <= 10) return "Intermediate";
    if (difficulty <= 15) return "Advanced";
    return "Master";
  };

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-7xl mx-auto px-4">
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-white mb-4">Security Labs</h1>
          {progress && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                <p className="text-gray-400 text-sm">Total Labs Completed</p>
                <p className="text-3xl font-bold text-cyan-400">
                  {progress.completed_labs}/{progress.total_labs}
                </p>
              </div>
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                <p className="text-gray-400 text-sm">Total Points</p>
                <p className="text-3xl font-bold text-yellow-400">
                  {progress.total_points} XP
                </p>
              </div>
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                <p className="text-gray-400 text-sm">Completion Rate</p>
                <p className="text-3xl font-bold text-green-400">
                  {progress.total_labs > 0
                    ? Math.round(
                        (progress.completed_labs / progress.total_labs) * 100
                      )
                    : 0}
                  %
                </p>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-700 rounded-lg flex items-start space-x-3">
            <AlertCircle className="text-red-500 flex-shrink-0" size={20} />
            <div>
              <p className="text-red-200 font-semibold">Error</p>
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          </div>
        )}

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="relative">
              <Search
                className="absolute left-3 top-3 text-gray-500"
                size={20}
              />
              <input
                type="text"
                placeholder="Search labs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>

            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="all">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat.replace("_", " ").toUpperCase()}
                </option>
              ))}
            </select>

            <select
              value={difficultyFilter}
              onChange={(e) => setDifficultyFilter(e.target.value)}
              className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="all">All Difficulties</option>
              <option value="1-5">Beginner (1-5)</option>
              <option value="6-10">Intermediate (6-10)</option>
              <option value="11-15">Advanced (11-15)</option>
              <option value="16-20">Master (16-20)</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4"></div>
            <p className="text-gray-300">Loading labs...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredLabs.map((lab) => (
              <div
                key={lab.id}
                className="bg-gray-800 border border-gray-700 rounded-lg hover:border-cyan-500 transition-all hover:shadow-lg hover:shadow-cyan-500/20 overflow-hidden group"
              >
                <div className="p-6">
                  <div className="flex items-start justify-between mb-3">
                    <span className="px-2 py-1 bg-blue-900/50 text-blue-300 text-xs font-medium rounded">
                      {lab.category?.replace("_", " ").toUpperCase()}
                    </span>
                    <span
                      className={`px-2 py-1 text-xs font-medium rounded border ${getDifficultyColor(
                        lab.difficulty || 1
                      )}`}
                    >
                      {getDifficultyLabel(lab.difficulty || 1)}
                    </span>
                  </div>

                  <h3 className="text-lg font-bold text-white mb-2 group-hover:text-cyan-400 transition">
                    {lab.title}
                  </h3>

                  <p className="text-gray-400 text-sm mb-4 line-clamp-2">
                    {lab.description}
                  </p>

                  <div className="flex items-center justify-between pt-4 border-t border-gray-700">
                    <span className="text-yellow-400 font-semibold">
                      +{lab.points || 100} XP
                    </span>
                    <button
                      onClick={() => navigate(`/lab/${lab.id}`)}
                      className="flex items-center space-x-1 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition"
                    >
                      <Play size={16} />
                      <span>Start</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {filteredLabs.length === 0 && !loading && !error && (
          <div className="text-center py-12">
            <p className="text-gray-400 text-lg">
              No labs found matching your filters.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;
