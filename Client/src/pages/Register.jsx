import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { registerUser, clearError } from "../features/authSlice";
import { useNavigate, Link } from "react-router-dom";
import toast from "react-hot-toast";
import { Zap, Mail, Lock, User, ArrowRight, Loader2 } from "lucide-react";

const Register = () => {
  const [username, setUsername] = useState("");
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

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !email || !password) return toast.error("Please fill in all fields.");
    const res = await dispatch(registerUser({ username, email, password }));
    if (res.meta.requestStatus === "fulfilled") {
      toast.success("Account created! Please sign in.");
      navigate("/login");
    }
  };

  const fields = [
    { label: "Username", type: "text", value: username, set: setUsername, icon: User, placeholder: "Choose a username" },
    { label: "Email address", type: "email", value: email, set: setEmail, icon: Mail, placeholder: "you@example.com" },
    { label: "Password", type: "password", value: password, set: setPassword, icon: Lock, placeholder: "Create a password" },
  ];

  return (
    <div className="auth-page">
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
            justifyContent: "center", boxShadow: "var(--glow-sm)"
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

        <div style={{ marginBottom: "1.75rem" }}>
          <h1 style={{
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: "1.5rem", fontWeight: 700,
            letterSpacing: "-0.03em", color: "var(--fg)", marginBottom: "0.375rem"
          }}>
            Create your account
          </h1>
          <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
            Get started with ProjectFlow for free
          </p>
        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {fields.map(({ label, type, value, set, icon: Icon, placeholder }) => (
            <div key={label} style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
              <label style={{ fontSize: "0.8rem", fontWeight: 500, color: "var(--fg-muted)" }}>
                {label}
              </label>
              <div style={{ position: "relative" }}>
                <Icon
                  size={15} strokeWidth={1.5}
                  style={{
                    position: "absolute", left: "0.75rem", top: "50%",
                    transform: "translateY(-50%)", color: "var(--fg-muted)"
                  }}
                />
                <input
                  type={type}
                  value={value}
                  onChange={(e) => set(e.target.value)}
                  placeholder={placeholder}
                  className="input"
                  style={{ paddingLeft: "2.25rem" }}
                />
              </div>
            </div>
          ))}

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "0.5rem", height: "2.75rem" }}
          >
            {loading ? (
              <><Loader2 size={16} className="animate-spin" /> Creating account...</>
            ) : (
              <>Create account <ArrowRight size={15} /></>
            )}
          </button>
        </form>

        <p style={{
          marginTop: "1.5rem", textAlign: "center",
          fontSize: "0.8rem", color: "var(--fg-muted)"
        }}>
          Already have an account?{" "}
          <Link to="/login" style={{
            color: "var(--accent)", fontWeight: 500,
            textDecoration: "none"
          }}>
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Register;