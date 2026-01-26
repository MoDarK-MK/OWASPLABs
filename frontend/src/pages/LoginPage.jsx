import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../App";
import { AlertCircle, CheckCircle, Eye, EyeOff } from "lucide-react";

const LoginPage = ({ onLogin }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [success, setSuccess] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await api.post("/api/auth/login", {
        username,
        password,
      });

      onLogin(response.data.token, response.data.user);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.error || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      const response = await api.post("/api/auth/register", {
        username,
        password,
        email,
      });

      setSuccess("Registration successful! You can now login.");
      setUsername("");
      setPassword("");
      setEmail("");
      setIsRegister(false);
    } catch (err) {
      setError(err.response?.data?.error || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center px-4 py-8">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-10 animate-fade-in">
          <div className="inline-block mb-4 p-4 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-2xl shadow-lg shadow-cyan-500/50">
            <div className="text-5xl">🛡️</div>
          </div>
          <h1 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 mb-3">
            OWASP Labs
          </h1>
          <p className="text-gray-300 text-lg font-medium">
            Cybersecurity Training Platform
          </p>
        </div>

        {/* Form Container */}
        <div className="backdrop-blur-xl bg-gradient-to-br from-slate-800/80 to-slate-900/80 border border-slate-700/50 rounded-2xl p-8 shadow-2xl hover:shadow-xl hover:shadow-cyan-500/10 transition-all duration-300">
          {error && (
            <div className="mb-6 p-4 bg-gradient-to-r from-red-500/10 to-red-600/10 border border-red-500/50 rounded-xl flex items-start space-x-3 animate-pulse">
              <AlertCircle
                className="text-red-400 flex-shrink-0 mt-0.5"
                size={20}
              />
              <div>
                <p className="text-red-200 font-semibold text-sm">Error</p>
                <p className="text-red-300 text-sm mt-1">{error}</p>
              </div>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 bg-gradient-to-r from-green-500/10 to-emerald-600/10 border border-green-500/50 rounded-xl flex items-start space-x-3 animate-pulse">
              <CheckCircle
                className="text-green-400 flex-shrink-0 mt-0.5"
                size={20}
              />
              <div>
                <p className="text-green-200 font-semibold text-sm">Success</p>
                <p className="text-green-300 text-sm mt-1">{success}</p>
              </div>
            </div>
          )}

          <form
            onSubmit={isRegister ? handleRegister : handleLogin}
            className="space-y-5"
          >
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-200"
              />
            </div>

            {isRegister && (
              <div>
                <label className="block text-sm font-semibold text-gray-200 mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="your@email.com"
                  required={isRegister}
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-200"
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="admin123"
                  required
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-200 pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 transition-colors"
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-700 text-white font-bold py-3 rounded-lg transition-all duration-200 flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/25 hover:shadow-xl hover:shadow-cyan-500/40 disabled:shadow-none"
            >
              {loading ? (
                <>
                  <div className="animate-spin h-5 w-5 border-2 border-white border-t-transparent rounded-full"></div>
                  <span>{isRegister ? "Registering..." : "Logging in..."}</span>
                </>
              ) : (
                <span>{isRegister ? "Register" : "Login"}</span>
              )}
            </button>
          </form>

          {/* Toggle Auth Mode */}
          <div className="mt-8 pt-6 border-t border-slate-700/50 text-center">
            <p className="text-slate-400 text-sm mb-4">
              {isRegister
                ? "Already have an account?"
                : "Don't have an account?"}
            </p>
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setError("");
                setSuccess("");
              }}
              className="text-cyan-400 hover:text-cyan-300 font-semibold transition duration-200 hover:underline"
            >
              {isRegister ? "Back to Login" : "Create Account"}
            </button>
          </div>
        </div>

        {/* Demo Credentials */}
        <div className="mt-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-xl text-center">
          <p className="text-blue-300 text-xs font-semibold mb-2">
            DEMO CREDENTIALS
          </p>
          <p className="text-blue-200 text-sm font-mono">
            Username: <span className="font-bold">admin</span>
          </p>
          <p className="text-blue-200 text-sm font-mono">
            Password: <span className="font-bold">admin123</span>
          </p>
        </div>

        <p className="text-center text-slate-400 text-xs mt-6 opacity-70">
          For educational purposes only © OWASP Foundation
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
