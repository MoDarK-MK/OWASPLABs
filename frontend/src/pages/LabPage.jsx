import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api } from "../App";
import {
  ChevronLeft,
  BookOpen,
  Lightbulb,
  Send,
  CheckCircle,
  AlertCircle,
} from "lucide-react";

const LabPage = () => {
  const { labId } = useParams();
  const navigate = useNavigate();
  const [lab, setLab] = useState(null);
  const [loading, setLoading] = useState(true);
  const [flag, setFlag] = useState("");
  const [hintLevel, setHintLevel] = useState(0);
  const [hint, setHint] = useState("");
  const [result, setResult] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    fetchLab();
  }, [labId]);

  const fetchLab = async () => {
    try {
      const response = await api.get(`/api/labs/${labId}`);
      setLab(response.data);

      await api.post(`/api/labs/${labId}/start`);
    } catch (error) {
      console.error("Failed to fetch lab:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleGetHint = async () => {
    const nextLevel = hintLevel + 1;
    try {
      const response = await api.get(
        `/api/labs/${labId}/hint?level=${nextLevel}`
      );
      setHint(response.data.hint);
      setHintLevel(nextLevel);
    } catch (error) {
      console.error("Failed to fetch hint:", error);
    }
  };

  const handleSubmitFlag = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);

    try {
      const response = await api.post(`/api/labs/${labId}/submit`, { flag });
      setResult(response.data);
      if (response.data.success) {
        setFlag("");
      }
    } catch (error) {
      setResult(
        error.response?.data || { success: false, message: "Submission failed" }
      );
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-500 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-gray-300">Loading lab...</p>
        </div>
      </div>
    );
  }

  if (!lab) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <p className="text-red-400">Lab not found</p>
      </div>
    );
  }

  const getDifficultyColor = (difficulty) => {
    if (difficulty <= 5) return "text-green-400";
    if (difficulty <= 10) return "text-yellow-400";
    if (difficulty <= 15) return "text-orange-400";
    return "text-red-400";
  };

  return (
    <div className="min-h-screen bg-gray-900 py-8">
      <div className="max-w-7xl mx-auto px-4">
        {}
        <button
          onClick={() => navigate("/dashboard")}
          className="flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 mb-6 transition"
        >
          <ChevronLeft size={20} />
          <span>Back to Labs</span>
        </button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {}
          <div className="lg:col-span-2 space-y-6">
            {}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h1 className="text-3xl font-bold text-white mb-2">
                    {lab.title}
                  </h1>
                  <div className="flex items-center space-x-4">
                    <span className="px-3 py-1 bg-blue-900 text-blue-200 rounded-full text-sm font-medium">
                      {lab.category.replace("_", " ").toUpperCase()}
                    </span>
                    <span
                      className={`px-3 py-1 bg-gray-700 ${getDifficultyColor(
                        lab.difficulty
                      )} rounded-full text-sm font-medium`}
                    >
                      Level {lab.difficulty}
                    </span>
                    <span className="px-3 py-1 bg-yellow-900 text-yellow-200 rounded-full text-sm font-medium">
                      {lab.points} XP
                    </span>
                  </div>
                </div>
              </div>

              <p className="text-gray-300 leading-relaxed">{lab.description}</p>
            </div>

            {}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <div className="flex items-center space-x-2 mb-4">
                <BookOpen size={20} className="text-cyan-400" />
                <h2 className="text-xl font-bold text-white">
                  Lab Instructions
                </h2>
              </div>
              <div className="text-gray-300 space-y-3">
                <p>1. Analyze the vulnerable application</p>
                <p>2. Identify the security vulnerability</p>
                <p>3. Exploit the vulnerability</p>
                <p>4. Capture the flag and submit it below</p>
              </div>
            </div>

            {}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-4">Submit Flag</h2>
              <form onSubmit={handleSubmitFlag} className="space-y-4">
                <input
                  type="text"
                  value={flag}
                  onChange={(e) => setFlag(e.target.value)}
                  placeholder="FLAG{...}"
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition font-mono"
                />
                <button
                  type="submit"
                  disabled={!flag || submitting}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white font-semibold py-3 rounded-lg transition flex items-center justify-center space-x-2"
                >
                  <Send size={20} />
                  <span>{submitting ? "Submitting..." : "Submit Flag"}</span>
                </button>
              </form>

              {result && (
                <div
                  className={`mt-4 p-4 rounded-lg border ${
                    result.success
                      ? "bg-green-900/20 border-green-700"
                      : "bg-red-900/20 border-red-700"
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    {result.success ? (
                      <CheckCircle
                        className="text-green-400 flex-shrink-0"
                        size={20}
                      />
                    ) : (
                      <AlertCircle
                        className="text-red-400 flex-shrink-0"
                        size={20}
                      />
                    )}
                    <div>
                      <p
                        className={`font-semibold ${
                          result.success ? "text-green-200" : "text-red-200"
                        }`}
                      >
                        {result.message}
                      </p>
                      {result.success && result.points && (
                        <p className="text-green-300 text-sm mt-1">
                          ✓ Earned {result.points} XP
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 h-fit">
            <div className="flex items-center space-x-2 mb-4">
              <Lightbulb size={20} className="text-yellow-400" />
              <h2 className="text-xl font-bold text-white">Hints</h2>
            </div>

            <p className="text-gray-400 text-sm mb-4">
              Get progressive hints if you're stuck. Each hint reveals more
              information.
            </p>

            {hint && (
              <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4 mb-4">
                <p className="text-blue-200 text-sm">
                  <strong>Hint {hintLevel}:</strong> {hint}
                </p>
              </div>
            )}

            {hintLevel < 5 && (
              <button
                onClick={handleGetHint}
                className="w-full bg-yellow-600 hover:bg-yellow-700 text-white font-semibold py-2 rounded-lg transition"
              >
                {hintLevel === 0
                  ? "Get First Hint"
                  : `Get Hint ${hintLevel + 1}`}
              </button>
            )}

            {hintLevel >= 5 && (
              <p className="text-gray-400 text-sm text-center py-2">
                All hints revealed
              </p>
            )}

            {}
            <div className="mt-6 pt-6 border-t border-gray-700 space-y-2 text-sm">
              <p className="text-gray-400">
                <strong>Category:</strong>
              </p>
              <p className="text-gray-300 ml-2">{lab.category}</p>
              <p className="text-gray-400 mt-4">
                <strong>Difficulty:</strong>
              </p>
              <div className="ml-2 w-full bg-gray-700 rounded-full h-2">
                <div
                  className={`h-full rounded-full ${
                    lab.difficulty <= 5
                      ? "bg-green-500"
                      : lab.difficulty <= 10
                      ? "bg-yellow-500"
                      : lab.difficulty <= 15
                      ? "bg-orange-500"
                      : "bg-red-500"
                  }`}
                  style={{ width: `${(lab.difficulty / 20) * 100}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LabPage;
