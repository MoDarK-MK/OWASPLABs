import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../App";
import { AlertCircle, CheckCircle } from "lucide-react";

const LoginPage = ({ onLogin }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [success, setSuccess] = useState("");
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
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="text-5xl mb-4">🛡️</div>
          <h1 className="text-4xl font-bold text-white mb-2">OWASP Labs</h1>
          <p className="text-gray-400">Professional Security Training Platform</p>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 shadow-2xl">
          {error && (
            <div className="mb-6 p-4 bg-red-900/20 border border-red-700 rounded-lg flex items-start space-x-3">
              <AlertCircle className="text-red-500 flex-shrink-0" size={20} />
              <div>
                <p className="text-red-200 font-semibold">Error</p>
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 bg-green-900/20 border border-green-700 rounded-lg flex items-start space-x-3">
              <CheckCircle className="text-green-500 flex-shrink-0" size={20} />
              <div>
                <p className="text-green-200 font-semibold">Success</p>
                <p className="text-green-300 text-sm">{success}</p>
              </div>
            </div>
          )}

          <form onSubmit={isRegister ? handleRegister : handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                required
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>

            {isRegister && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter email"
                  required={isRegister}
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white font-semibold py-3 rounded-lg transition flex items-center justify-center space-x-2"
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

          <div className="mt-6 pt-6 border-t border-gray-700 text-center">
            <p className="text-gray-400 text-sm mb-3">
              {isRegister ? "Already have an account?" : "Don't have an account?"}
            </p>
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setError("");
                setSuccess("");
              }}
              className="text-cyan-400 hover:text-cyan-300 font-medium transition"
            >
              {isRegister ? "Login" : "Register"}
            </button>
          </div>
        </div>

        <p className="text-center text-gray-500 text-sm mt-6">Demo: admin / admin123</p>
      </div>
    </div>
  );
};

export default LoginPage;
          </form>

          {}
          <div className="mt-6 p-4 bg-blue-900/20 border border-blue-700 rounded-lg">
            <p className="text-sm text-blue-300">
              <CheckCircle className="inline mr-2" size={16} />
              Demo credentials: <span className="font-mono">admin</span> /{" "}
              <span className="font-mono">admin123</span>
            </p>
          </div>
        </div>

        {}
        <p className="text-center text-gray-400 text-sm mt-6">
          For educational purposes only | OWASP Foundation
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
