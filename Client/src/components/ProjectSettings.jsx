import { format } from "date-fns";
import { Plus, Save } from "lucide-react";
import { useEffect, useState } from "react";
import AddProjectMember from "./AddProjectMember";

const Field = ({ label, children }) => (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
        <label style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--fg-muted)" }}>{label}</label>
        {children}
    </div>
)

export default function ProjectSettings({ project }) {
    const [formData, setFormData] = useState({
        name: "", description: "", status: "PLANNING", priority: "MEDIUM",
        start_date: "", end_date: "", progress: 0,
    });
    const [isDialogOpen, setIsDialogOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const set = (key, val) => setFormData(prev => ({ ...prev, [key]: val }))

    const handleSubmit = async (e) => {
        e.preventDefault();
        // API integration point
    };

    useEffect(() => {
        if (project) {
            setFormData({
                name: project.name || "",
                description: project.description || "",
                status: project.status || "PLANNING",
                priority: project.priority || "MEDIUM",
                start_date: project.start_date ? format(new Date(project.start_date), "yyyy-MM-dd") : "",
                end_date: project.end_date ? format(new Date(project.end_date), "yyyy-MM-dd") : "",
                progress: project.progress || 0,
            });
        }
    }, [project]);

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem", alignItems: "start" }} className="settings-grid">

            {/* Project Details */}
            <div style={{
                background: "var(--card)", backdropFilter: "blur(8px)",
                border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                padding: "1.25rem"
            }}>
                <h2 style={{
                    fontFamily: "'Space Grotesk', sans-serif",
                    fontWeight: 600, fontSize: "0.9rem",
                    color: "var(--fg)", marginBottom: "1.25rem",
                    letterSpacing: "-0.01em"
                }}>
                    Project Details
                </h2>

                <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    <Field label="Project Name">
                        <input
                            value={formData.name}
                            onChange={e => set("name", e.target.value)}
                            className="input" required
                        />
                    </Field>

                    <Field label="Description">
                        <textarea
                            value={formData.description}
                            onChange={e => set("description", e.target.value)}
                            className="input"
                            style={{ height: "5rem", resize: "vertical" }}
                        />
                    </Field>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                        <Field label="Status">
                            <select value={formData.status} onChange={e => set("status", e.target.value)} className="input">
                                <option value="PLANNING">Planning</option>
                                <option value="ACTIVE">Active</option>
                                <option value="ON_HOLD">On Hold</option>
                                <option value="COMPLETED">Completed</option>
                                <option value="CANCELLED">Cancelled</option>
                            </select>
                        </Field>
                        <Field label="Priority">
                            <select value={formData.priority} onChange={e => set("priority", e.target.value)} className="input">
                                <option value="LOW">Low</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="HIGH">High</option>
                            </select>
                        </Field>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                        <Field label="Start Date">
                            <input
                                type="date"
                                value={formData.start_date}
                                onChange={e => set("start_date", e.target.value)}
                                className="input"
                            />
                        </Field>
                        <Field label="End Date">
                            <input
                                type="date"
                                value={formData.end_date}
                                onChange={e => set("end_date", e.target.value)}
                                min={formData.start_date}
                                className="input"
                            />
                        </Field>
                    </div>

                    <Field label={`Progress · ${formData.progress}%`}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                            <input
                                type="range" min="0" max="100" step="5"
                                value={formData.progress}
                                onChange={e => set("progress", Number(e.target.value))}
                                style={{ width: "100%", accentColor: "var(--accent)", cursor: "pointer" }}
                            />
                            <div className="progress-track">
                                <div className="progress-fill" style={{ width: `${formData.progress}%` }} />
                            </div>
                        </div>
                    </Field>

                    <div style={{ display: "flex", justifyContent: "flex-end", paddingTop: "0.5rem", borderTop: "1px solid var(--border)" }}>
                        <button type="submit" disabled={isSubmitting} className="btn btn-primary btn-sm">
                            <Save size={14} strokeWidth={1.5} />
                            {isSubmitting ? "Saving..." : "Save Changes"}
                        </button>
                    </div>
                </form>
            </div>

            {/* Team Members */}
            <div style={{
                background: "var(--card)", backdropFilter: "blur(8px)",
                border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                padding: "1.25rem"
            }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.25rem" }}>
                    <h2 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontWeight: 600, fontSize: "0.9rem",
                        color: "var(--fg)", letterSpacing: "-0.01em"
                    }}>
                        Team Members
                        <span style={{ fontWeight: 400, color: "var(--fg-muted)", marginLeft: "0.375rem", fontSize: "0.8rem" }}>
                            ({project.members?.length || 0})
                        </span>
                    </h2>
                    <button
                        type="button"
                        onClick={() => setIsDialogOpen(true)}
                        className="btn btn-secondary btn-icon"
                        aria-label="Add member"
                    >
                        <Plus size={15} strokeWidth={1.5} />
                    </button>
                </div>

                {project.members?.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem", maxHeight: "20rem", overflowY: "auto" }} className="no-scrollbar">
                        {project.members.map((member, i) => (
                            <div key={i} style={{
                                display: "flex", alignItems: "center", justifyContent: "space-between",
                                padding: "0.625rem 0.875rem",
                                borderRadius: "var(--radius-md)",
                                background: "var(--bg-elevated)",
                                border: "1px solid var(--border)"
                            }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.625rem" }}>
                                    <div style={{
                                        width: 28, height: 28, borderRadius: "var(--radius-full)",
                                        background: "var(--accent-muted)",
                                        border: "1px solid var(--border-accent)",
                                        display: "flex", alignItems: "center", justifyContent: "center",
                                        fontSize: "0.65rem", fontWeight: 700, color: "var(--accent)",
                                        flexShrink: 0
                                    }}>
                                        {member?.user?.email?.[0]?.toUpperCase() || "?"}
                                    </div>
                                    <span style={{ fontSize: "0.8rem", color: "var(--fg)" }}>
                                        {member?.user?.email || "Unknown"}
                                    </span>
                                </div>
                                {project.team_lead === member?.user?.id && (
                                    <span style={{
                                        fontSize: "0.65rem", fontWeight: 600,
                                        background: "var(--accent-muted)", color: "var(--accent)",
                                        border: "1px solid var(--border-accent)",
                                        padding: "0.15rem 0.5rem", borderRadius: "var(--radius-full)",
                                        fontFamily: "'JetBrains Mono', monospace"
                                    }}>
                                        Lead
                                    </span>
                                )}
                            </div>
                        ))}
                    </div>
                ) : (
                    <div style={{ textAlign: "center", padding: "2rem 1rem" }}>
                        <p style={{ fontSize: "0.85rem", color: "var(--fg-muted)" }}>No members added yet</p>
                        <button
                            type="button"
                            onClick={() => setIsDialogOpen(true)}
                            className="btn btn-secondary btn-sm"
                            style={{ marginTop: "0.75rem" }}
                        >
                            <Plus size={13} /> Add Member
                        </button>
                    </div>
                )}

                <AddProjectMember isDialogOpen={isDialogOpen} setIsDialogOpen={setIsDialogOpen} />
            </div>

            <style>{`
                @media (max-width: 768px) {
                    .settings-grid { grid-template-columns: 1fr !important; }
                }
            `}</style>
        </div>
    );
}