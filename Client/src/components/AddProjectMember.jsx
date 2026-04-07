import { useState } from "react";
import { Mail, UserPlus, X } from "lucide-react";
import { useSelector } from "react-redux";
import { useSearchParams } from "react-router-dom";

const AddProjectMember = ({ isDialogOpen, setIsDialogOpen }) => {
    const [searchParams] = useSearchParams();
    const id = searchParams.get('id');

    const currentWorkspace = useSelector(state => state.workspace?.currentWorkspace || null);
    const project = currentWorkspace?.projects.find(p => p.id === id || p._id === id);
    const projectMemberEmails = Array.isArray(project?.members) ? project.members.map(m => m.user.email) : [];

    const [email, setEmail] = useState('');
    const [isAdding, setIsAdding] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        // API integration point
    };

    const availableMembers = currentWorkspace?.members.filter(
        m => !projectMemberEmails.includes(m.user.email)
    ) || [];

    if (!isDialogOpen) return null;

    return (
        <div className="overlay" onClick={e => e.target === e.currentTarget && setIsDialogOpen(false)}>
            <div className="dialog">
                {/* Header */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                    <div>
                        <h2 style={{
                            fontFamily: "'Space Grotesk', sans-serif",
                            fontWeight: 700, fontSize: "1.1rem",
                            letterSpacing: "-0.02em", color: "var(--fg)"
                        }}>
                            Add Member
                        </h2>
                        {project && (
                            <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginTop: "0.2rem" }}>
                                Project: <span style={{ color: "var(--accent)" }}>{project.name}</span>
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
                            Select Member
                        </label>
                        <div style={{ position: "relative" }}>
                            <Mail size={14} strokeWidth={1.5} style={{
                                position: "absolute", left: "0.75rem", top: "50%",
                                transform: "translateY(-50%)", color: "var(--fg-muted)"
                            }} />
                            <select
                                value={email}
                                onChange={e => setEmail(e.target.value)}
                                className="input"
                                style={{ paddingLeft: "2.25rem" }}
                                required
                            >
                                <option value="">Choose a workspace member...</option>
                                {availableMembers.map(member => (
                                    <option key={member.user.id} value={member.user.email}>
                                        {member.user.email}
                                    </option>
                                ))}
                            </select>
                        </div>
                        {availableMembers.length === 0 && (
                            <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginTop: "0.25rem" }}>
                                All workspace members are already in this project.
                            </p>
                        )}
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.625rem", paddingTop: "0.5rem", borderTop: "1px solid var(--border)" }}>
                        <button type="button" onClick={() => setIsDialogOpen(false)} className="btn btn-secondary btn-sm">
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={isAdding || !currentWorkspace || availableMembers.length === 0}
                            className="btn btn-primary btn-sm"
                        >
                            {isAdding ? "Adding..." : "Add Member"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default AddProjectMember;