import { useState } from "react";
import { Mail, UserPlus, X } from "lucide-react";
import { useSelector } from "react-redux";

const InviteMemberDialog = ({ isDialogOpen, setIsDialogOpen }) => {
    const currentWorkspace = useSelector(state => state.workspace?.currentWorkspace || null)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [formData, setFormData] = useState({ email: "", role: "org:member" })

    const handleSubmit = async (e) => {
        e.preventDefault()
        // API integration point
    }

    if (!isDialogOpen) return null

    return (
        <div className="overlay" onClick={e => e.target === e.currentTarget && setIsDialogOpen(false)}>
            <div className="dialog">
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                    <div>
                        <h2 style={{
                            fontFamily: "'Space Grotesk', sans-serif",
                            fontWeight: 700, fontSize: "1.1rem",
                            letterSpacing: "-0.02em", color: "var(--fg)"
                        }}>
                            Invite Team Member
                        </h2>
                        {currentWorkspace && (
                            <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginTop: "0.2rem" }}>
                                To: <span style={{ color: "var(--accent)" }}>{currentWorkspace.name}</span>
                            </p>
                        )}
                    </div>
                    <button onClick={() => setIsDialogOpen(false)} className="btn btn-ghost btn-icon">
                        <X size={16} strokeWidth={1.5} />
                    </button>
                </div>

                <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
                        <label style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--fg-muted)" }}>
                            Email Address
                        </label>
                        <div style={{ position: "relative" }}>
                            <Mail size={14} strokeWidth={1.5} style={{
                                position: "absolute", left: "0.75rem", top: "50%",
                                transform: "translateY(-50%)", color: "var(--fg-muted)"
                            }} />
                            <input
                                type="email"
                                value={formData.email}
                                onChange={e => setFormData({ ...formData, email: e.target.value })}
                                placeholder="colleague@company.com"
                                className="input"
                                style={{ paddingLeft: "2.25rem" }}
                                required
                            />
                        </div>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
                        <label style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--fg-muted)" }}>Role</label>
                        <select
                            value={formData.role}
                            onChange={e => setFormData({ ...formData, role: e.target.value })}
                            className="input"
                        >
                            <option value="org:member">Member</option>
                            <option value="org:admin">Admin</option>
                        </select>
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.625rem", paddingTop: "0.5rem", borderTop: "1px solid var(--border)" }}>
                        <button type="button" onClick={() => setIsDialogOpen(false)} className="btn btn-secondary btn-sm">
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting || !currentWorkspace}
                            className="btn btn-primary btn-sm"
                        >
                            {isSubmitting ? "Sending..." : "Send Invitation"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    )
}

export default InviteMemberDialog