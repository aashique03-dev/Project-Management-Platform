import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { loginUser, clearError } from "../features/authSlice";
import { useNavigate, Link } from "react-router-dom";
import toast from "react-hot-toast";
import { Zap, Mail, Lock, ArrowRight, Loader2 } from "lucide-react";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { loading, error, isAuthenticated } = useSelector((state) => state.auth);

  useEffect(() => {
    if (isAuthenticated) navigate("/");
    if (error) {
      toast.error(error);
      dispatch(clearError());
    }
  }, [isAuthenticated, error, navigate, dispatch]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email || !password) return toast.error("Please fill in all fields.");
    dispatch(loginUser({ email, password }));
  };

  return (
    <div className="auth-page">
      {/* Ambient background */}
      <div className="ambient-bg">
        <div className="ambient-orb ambient-orb-1" />
        <div className="ambient-orb ambient-orb-2" />
      </div>

      <div className="auth-card" style={{ position: "relative", zIndex: 1 }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.625rem", marginBottom: "2rem" }}>
          <div style={{
            width: 34, height: 34, borderRadius: "var(--radius-md)",
            background: "var(--accent)", display: "flex", alignItems: "center",
            justifyContent: "center", flexShrink: 0,
            boxShadow: "var(--glow-sm)"
          }}>
            <Zap size={17} color="var(--accent-fg)" strokeWidth={2.5} />
          </div>
          <span style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontWeight: 700, fontSize: "1.1rem",
            letterSpacing: "-0.02em", color: "var(--fg)"
          }}>
            ProjectFlow
          </span>
        </div>

        {/* Header */}
        <div style={{ marginBottom: "1.75rem" }}>
          <h1 style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: "1.5rem", fontWeight: 700,
            letterSpacing: "-0.03em", color: "var(--fg)",
            marginBottom: "0.375rem"
          }}>
            Welcome back
          </h1>
          <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
            Sign in to continue to your workspace
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {/* Email */}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
            <label style={{
              fontSize: "0.8rem", fontWeight: 500,
              color: "var(--fg-muted)", letterSpacing: "0.01em"
            }}>
              Email address
            </label>
            <div style={{ position: "relative" }}>
              <Mail
                size={15} strokeWidth={1.5}
                style={{
                  position: "absolute", left: "0.75rem", top: "50%",
                  transform: "translateY(-50%)", color: "var(--fg-muted)"
                }}
              />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="input"
                style={{ paddingLeft: "2.25rem" }}
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
            <label style={{
              fontSize: "0.8rem", fontWeight: 500,
              color: "var(--fg-muted)", letterSpacing: "0.01em"
            }}>
              Password
            </label>
            <div style={{ position: "relative" }}>
              <Lock
                size={15} strokeWidth={1.5}
                style={{
                  position: "absolute", left: "0.75rem", top: "50%",
                  transform: "translateY(-50%)", color: "var(--fg-muted)"
                }}
              />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="input"
                style={{ paddingLeft: "2.25rem" }}
              />
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "0.5rem", height: "2.75rem" }}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Signing in...
              </>
            ) : (
              <>
                Sign in
                <ArrowRight size={15} strokeWidth={2} />
              </>
            )}
          </button>
        </form>

        {/* Footer */}
        <p style={{
          marginTop: "1.5rem", textAlign: "center",
          fontSize: "0.8rem", color: "var(--fg-muted)"
        }}>
          Don't have an account?{" "}
          <Link to="/register" style={{
            color: "var(--accent)", fontWeight: 500,
            textDecoration: "none",
            transition: "opacity 200ms"
          }}>
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Login;