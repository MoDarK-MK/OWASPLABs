import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ChevronLeft,
  Lightbulb,
  Send,
  CheckCircle,
  AlertCircle,
  Code,
  Terminal,
  Eye,
  EyeOff,
  Play,
  ExternalLink,
} from "lucide-react";
import api from "../utils/api";

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
  const [showVulnerableCode, setShowVulnerableCode] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [labUrl, setLabUrl] = useState(null);

  const labChallenges = {
    1: {
      title: "SQL Injection - Login Bypass",
      category: "sql_injection",
      difficulty: "Easy",
      points: 100,
      flag: "FLAG{sqli_basic}",
      description:
        "The application has a vulnerable login form. Bypass it using SQL injection.",
      scenario:
        "A web application uses string concatenation to build SQL queries without sanitization. Try to bypass the login form.",
      vulnerableCode: `username = request.form['username']\npassword = request.form['password']\nquery = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"\nresult = db.execute(query)`,
      payload: `Username: admin' --\nPassword: (anything)`,
      hint1:
        "Try using SQL comment operators like -- or /* to bypass the password check.",
      hint2: "The payload might look like: admin' --",
      hint3:
        "SQL comments ignore everything after them. If you enter \"admin' --\", the query becomes: SELECT * FROM users WHERE username='admin' -- AND password='...'",
    },
    2: {
      title: "XSS - Stored Cross-Site Scripting",
      category: "xss",
      difficulty: "Medium",
      points: 150,
      flag: "FLAG{xss_stored}",
      description:
        "The comment section stores user input without sanitization. Store JavaScript code.",
      scenario:
        "A comment system displays comments from database without escaping HTML/JavaScript.",
      vulnerableCode: `comment = request.form['comment']\ndb.insert('comments', {'text': comment})\n\n<!-- In template: -->\n{% for comment in comments %}\n  <p>{{ comment.text }}</p>\n{% endfor %}`,
      payload: `<img src=x onerror="alert('XSS Vulnerability Found!')">`,
      hint1:
        "You need to inject JavaScript code that will execute when the page loads.",
      hint2: 'Try using <script> tags or event handlers like <img onerror="">',
      hint3:
        'A simple payload: <script>alert("XSS")</script> or <img src=x onerror="alert(\'XSS\')">',
    },
    3: {
      title: "CSRF - Cross-Site Request Forgery",
      category: "csrf",
      difficulty: "Hard",
      points: 200,
      flag: "FLAG{csrf_attack}",
      description:
        "The admin panel doesn't verify CSRF tokens. Forge a request from another site.",
      scenario:
        "An admin is logged in. Create a page that makes them perform unintended actions.",
      vulnerableCode: `@app.route('/api/admin/settings', methods=['POST'])\n@require_auth\ndef change_settings():\n    setting = request.form['setting']\n    value = request.form['value']\n    # No CSRF token verification!\n    save_setting(setting, value)\n    return {'success': True}`,
      payload: `<form action="http://localhost:5000/api/admin/settings" method="POST">\n  <input type="hidden" name="setting" value="admin_email">\n  <input type="hidden" name="value" value="attacker@evil.com">\n</form>\n<script>document.forms[0].submit();</script>`,
      hint1:
        "CSRF works because browsers auto-send cookies with requests to the same domain.",
      hint2: "Create a form that auto-submits to the vulnerable endpoint.",
      hint3:
        "The form should POST to admin.app.com/api/admin/settings when the admin is logged in.",
    },
    4: {
      title: "IDOR - Insecure Direct Object Reference",
      category: "idor",
      difficulty: "Medium",
      points: 150,
      flag: "FLAG{idor_exposed}",
      description:
        "The API returns user data based on ID without authorization. Access others' data.",
      scenario:
        "API endpoint: GET /api/user/profile/123 returns user profile. Try changing the ID.",
      vulnerableCode: `@app.route('/api/user/profile/<int:user_id>', methods=['GET'])\ndef get_profile(user_id):\n    user = db.query('SELECT * FROM users WHERE id = ?', user_id)\n    # No check if current user is allowed to see this profile!\n    return user.to_json()`,
      payload: `Try accessing different user IDs:\n/api/user/profile/1\n/api/user/profile/2\n/api/user/profile/3\n(Admin is usually ID 1)`,
      hint1: "Try incrementing or decrementing the user ID in the URL.",
      hint2:
        "If you're user 5, try accessing /api/user/profile/1, /2, /3, /4, /6, etc.",
      hint3:
        "Admin user usually has ID 1. Try accessing their profile directly.",
    },
    5: {
      title: "RCE - Remote Code Execution",
      category: "rce",
      difficulty: "Hard",
      points: 250,
      flag: "FLAG{rce_pwned}",
      description:
        "The application executes user input as code. Execute commands on the server.",
      scenario:
        "An image processing app passes user input directly to system commands.",
      vulnerableCode: `import subprocess\n\nfilename = request.form['filename']\n# Dangerous! User input directly in shell command\nresult = subprocess.run(f"convert {filename} output.jpg", shell=True)`,
      hint1: "You can chain commands using ; or | in shell.",
      hint2: "Try: image.jpg; whoami to see who the process runs as.",
      hint3:
        "Command chaining with & or && might work: filename.jpg && cat /etc/passwd",
    },
    6: {
      title: "SSRF - Server-Side Request Forgery",
      category: "ssrf",
      difficulty: "Hard",
      points: 200,
      flag: "FLAG{ssrf_internal}",
      description:
        "The server fetches URLs without validation. Access internal services.",
      scenario:
        "API endpoint downloads images from URLs. Access internal APIs.",
      vulnerableCode: `import requests\n\nurl = request.form['image_url']\n# No validation! User can specify any URL\nresponse = requests.get(url)\nprocess_image(response.content)`,
      hint1:
        "Try accessing internal URLs like http://localhost:8080 or http://127.0.0.1:6379",
      hint2:
        "Common internal services: localhost:8080, 127.0.0.1:3000, internal-api.local",
      hint3:
        "You can also access metadata: http://169.254.169.254/latest/meta-data",
    },
    7: {
      title: "XXE - XML External Entity Injection",
      category: "xxe",
      difficulty: "Hard",
      points: 250,
      flag: "FLAG{xxe_file_read}",
      description:
        "The XML parser processes external entities. Read local files.",
      scenario:
        "An API accepts XML uploads for configuration. XXE allows file disclosure.",
      vulnerableCode: `from xml.etree import ElementTree as ET\n\nxml_data = request.data\n# Vulnerable XML parser - processes external entities!\nroot = ET.fromstring(xml_data)\nprocess_config(root)`,
      hint1: "Define a DOCTYPE with ENTITY pointing to a file.",
      hint2: 'Use SYSTEM keyword: <!ENTITY xxe SYSTEM "file:///etc/passwd">',
      hint3:
        'XXE payload:\n<?xml version="1.0"?>\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<root>&xxe;</root>',
    },
    8: {
      title: "Command Injection - OS Command Execution",
      category: "command_injection",
      difficulty: "Very Hard",
      points: 300,
      flag: "FLAG{cmd_injection_pwned}",
      description:
        "The application executes system commands. Inject commands to read files.",
      scenario: "A network utility pings servers by taking user input.",
      vulnerableCode: `import subprocess\n\nhost = request.form['host']\n# Vulnerable - directly concatenates user input\nresult = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)\nreturn result.stdout`,
      hint1: "Use command separators: ; | || && ` $() to chain commands",
      hint2: "Try: google.com; cat /etc/passwd",
      hint3: "Command substitution: google.com$(cat /etc/passwd)",
    },
  };

  useEffect(() => {
    fetchLab();
  }, [labId]);

  const fetchLab = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/api/labs/${labId}`);
      setLab(response.data);
      await api.post(`/api/labs/${labId}/start`);
    } catch (error) {
      console.error("Failed to fetch lab:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleGetHint = () => {
    const nextLevel = hintLevel + 1;
    const challenge = labChallenges[labId];

    if (nextLevel === 1 && challenge?.hint1) {
      setHint(challenge.hint1);
      setHintLevel(1);
    } else if (nextLevel === 2 && challenge?.hint2) {
      setHint(challenge.hint2);
      setHintLevel(2);
    } else if (nextLevel === 3 && challenge?.hint3) {
      setHint(challenge.hint3);
      setHintLevel(3);
    } else {
      setHint("No more hints available!");
    }
  };

  const handleSubmitFlag = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setResult(null);

    try {
      const response = await api.post(`/api/labs/${labId}/submit`, { flag });

      if (response.data.success) {
        setResult({
          success: true,
          message: response.data.message,
          points: response.data.points,
        });
        setFlag("");
      } else {
        setResult({ success: false, message: response.data.message });
      }
    } catch (error) {
      setResult({
        success: false,
        message: error.response?.data?.message || "Submission failed",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleLaunchLab = async () => {
    setLaunching(true);
    try {
      const response = await api.get(`/api/labs/${labId}/launch`);
      if (response.data.practical_lab) {
        setLabUrl(response.data.practical_lab);
        // Open lab in new window after 2 seconds
        setTimeout(() => {
          window.open(response.data.practical_lab, "_blank");
        }, 500);
      } else {
        setResult({
          success: false,
          message: response.data.instructions || "Lab not available",
        });
      }
    } catch (error) {
      setResult({
        success: false,
        message: error.response?.data?.error || "Failed to launch lab",
      });
    } finally {
      setLaunching(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin h-12 w-12 border-4 border-cyan-400 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-slate-300">Loading challenge...</p>
        </div>
      </div>
    );
  }

  const challenge = labChallenges[labId];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 py-12 px-4">
      <div className="max-w-6xl mx-auto">
        <button
          onClick={() => navigate("/dashboard")}
          className="flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 mb-8 transition"
        >
          <ChevronLeft size={24} />
          <span>Back to Labs</span>
        </button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <div className="backdrop-blur-xl bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-xl p-8 mb-8">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h1 className="text-4xl font-black text-white mb-2">
                    {challenge?.title || lab?.title}
                  </h1>
                  <p className="text-slate-400 text-lg">
                    {challenge?.description}
                  </p>
                </div>
                <div
                  className={`px-4 py-2 rounded-lg font-bold text-sm ${
                    challenge?.difficulty === "Easy"
                      ? "bg-green-500/20 text-green-400"
                      : challenge?.difficulty === "Medium"
                        ? "bg-yellow-500/20 text-yellow-400"
                        : challenge?.difficulty === "Hard"
                          ? "bg-red-500/20 text-red-400"
                          : "bg-purple-500/20 text-purple-400"
                  }`}
                >
                  {challenge?.difficulty}
                </div>
              </div>
              <div className="flex items-center space-x-6">
                <span className="text-slate-400">
                  Category:{" "}
                  <span className="text-cyan-400 font-bold">
                    {challenge?.category}
                  </span>
                </span>
                <span className="text-slate-400">
                  Points:{" "}
                  <span className="text-yellow-400 font-bold">
                    {challenge?.points}
                  </span>
                </span>
              </div>
            </div>

            <div className="backdrop-blur-xl bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-xl p-8 mb-8">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center space-x-2">
                <Code size={24} className="text-blue-400" />
                <span>Challenge Scenario</span>
              </h2>
              <p className="text-slate-300 leading-relaxed mb-6">
                {challenge?.scenario}
              </p>

              <div className="mb-6">
                <button
                  onClick={() => setShowVulnerableCode(!showVulnerableCode)}
                  className="flex items-center space-x-2 text-red-400 hover:text-red-300 font-semibold mb-4 transition"
                >
                  {showVulnerableCode ? (
                    <EyeOff size={20} />
                  ) : (
                    <Eye size={20} />
                  )}
                  <span>
                    {showVulnerableCode ? "Hide" : "Show"} Vulnerable Code &
                    Payload
                  </span>
                </button>

                {showVulnerableCode && (
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-semibold text-red-300 mb-2">
                        Vulnerable Code:
                      </h4>
                      <div className="bg-slate-950/80 border border-red-500/30 rounded-lg p-6 font-mono text-sm text-red-200 overflow-x-auto whitespace-pre-wrap">
                        {challenge?.vulnerableCode}
                      </div>
                    </div>

                    {challenge?.payload && (
                      <div>
                        <h4 className="text-sm font-semibold text-yellow-300 mb-2">
                          Working Payload:
                        </h4>
                        <div className="bg-slate-950/80 border border-yellow-500/30 rounded-lg p-6 font-mono text-sm text-yellow-200 overflow-x-auto whitespace-pre-wrap">
                          {challenge?.payload}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="lg:col-span-1">
            {/* Launch Lab Section */}
            <div className="backdrop-blur-xl bg-gradient-to-br from-orange-500/10 to-red-600/10 border border-orange-500/30 rounded-xl p-6 mb-6 sticky top-8">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
                <Terminal size={24} className="text-orange-400" />
                <span>Practical Lab</span>
              </h3>

              {labUrl ? (
                <div className="space-y-4">
                  <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4">
                    <p className="text-green-300 text-sm font-semibold">
                      ✓ Lab Running
                    </p>
                    <p className="text-green-200 text-xs mt-1">{labUrl}</p>
                  </div>
                  <button
                    onClick={() => window.open(labUrl, "_blank")}
                    className="w-full px-4 py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white font-bold rounded-lg transition flex items-center justify-center space-x-2"
                  >
                    <ExternalLink size={20} />
                    <span>Open Lab Environment</span>
                  </button>
                </div>
              ) : (
                <button
                  onClick={handleLaunchLab}
                  disabled={launching}
                  className="w-full px-4 py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 disabled:from-slate-600 disabled:to-slate-700 text-white font-bold rounded-lg transition flex items-center justify-center space-x-2"
                >
                  <Play size={20} />
                  <span>{launching ? "Launching..." : "Launch Lab"}</span>
                </button>
              )}
            </div>

            <div className="backdrop-blur-xl bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-cyan-500/30 rounded-xl p-6 sticky top-8">
              <h3 className="text-xl font-bold text-white mb-4 flex items-center space-x-2">
                <CheckCircle size={24} className="text-cyan-400" />
                <span>Submit Flag</span>
              </h3>

              <form onSubmit={handleSubmitFlag} className="space-y-4">
                <input
                  type="text"
                  placeholder="FLAG{...}"
                  value={flag}
                  onChange={(e) => setFlag(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-cyan-500/30 rounded-lg text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none transition"
                />

                <button
                  type="submit"
                  disabled={submitting || !flag.trim()}
                  className="w-full px-4 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-700 text-white font-bold rounded-lg transition flex items-center justify-center space-x-2"
                >
                  <Send size={20} />
                  <span>{submitting ? "Submitting..." : "Submit Flag"}</span>
                </button>
              </form>

              {result && (
                <div
                  className={`mt-6 p-4 rounded-lg border ${
                    result.success
                      ? "bg-green-500/10 border-green-500/30 text-green-300"
                      : "bg-red-500/10 border-red-500/30 text-red-300"
                  }`}
                >
                  <p className="font-semibold mb-2 flex items-center space-x-2">
                    {result.success ? (
                      <CheckCircle size={20} />
                    ) : (
                      <AlertCircle size={20} />
                    )}
                    <span>{result.message}</span>
                  </p>
                  {result.success && result.points && (
                    <p className="text-sm">
                      You earned{" "}
                      <span className="font-bold text-yellow-400">
                        +{result.points} XP
                      </span>
                    </p>
                  )}
                </div>
              )}

              <div className="mt-6 pt-6 border-t border-slate-700/50">
                <button
                  onClick={handleGetHint}
                  disabled={hintLevel >= 3}
                  className="w-full px-4 py-3 bg-gradient-to-r from-yellow-500/20 to-orange-500/20 hover:from-yellow-500/30 hover:to-orange-500/30 disabled:from-slate-600/20 disabled:to-slate-700/20 text-yellow-300 disabled:text-slate-500 font-bold rounded-lg transition border border-yellow-500/30 disabled:border-slate-600/30 flex items-center justify-center space-x-2"
                >
                  <Lightbulb size={20} />
                  <span>
                    {hintLevel === 0
                      ? "Get Hint"
                      : hintLevel === 3
                        ? "No More Hints"
                        : "Next Hint"}
                  </span>
                </button>

                {hint && (
                  <div className="mt-4 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                    <p className="text-yellow-300 text-sm leading-relaxed whitespace-pre-wrap">
                      {hint}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LabPage;
