import { useState } from "react";
import { X } from "lucide-react";
import { useSelector, useDispatch } from "react-redux";
import { createProject } from "../features/workspaceSlice";

const CreateProjectDialog = ({ isDialogOpen, setIsDialogOpen }) => {
    const dispatch = useDispatch()
    const { currentWorkspace } = useSelector(state => state.workspace)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [formData, setFormData] = useState({
        name: "", description: "", status: "PLANNING", priority: "MEDIUM",
        start_date: "", end_date: "", team_members: [], team_lead: "", progress: 0
    })

    const set = (key, val) => setFormData(prev => ({ ...prev, [key]: val }))

    const handleSubmit = async (e) => {
        e.preventDefault()
        setIsSubmitting(true)
        try {
            await dispatch(createProject(formData)).unwrap()
            setIsDialogOpen(false)
        } catch (err) {
            console.error(err)
        } finally {
            setIsSubmitting(false)
        }
    }

    const removeTeamMember = (email) =>
        set("team_members", formData.team_members.filter(m => m !== email))

    if (!isDialogOpen) return null

    return (
        <div className="overlay" onClick={e => e.target === e.currentTarget && setIsDialogOpen(false)}>
            <div className="dialog" style={{ maxWidth: "32rem", maxHeight: "90vh", overflowY: "auto" }}>
                {/* Header */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                    <div>
                        <h2 style={{
                            fontFamily: "'Space Grotesk', sans-serif",
                            fontWeight: 700, fontSize: "1.1rem",
                            letterSpacing: "-0.02em", color: "var(--fg)"
                        }}>
                            Create New Project
                        </h2>
                        {currentWorkspace && (
                            <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginTop: "0.2rem" }}>
                                Workspace: <span style={{ color: "var(--accent)" }}>{currentWorkspace.name}</span>
                            </p>
                        )}
                    </div>
                    <button
                        onClick={() => setIsDialogOpen(false)}
                        className="btn btn-ghost btn-icon"
                        aria-label="Close"
                    >
                        <X size={16} strokeWidth={1.5} />
                    </button>
                </div>

                <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    <Field label="Project Name">
                        <input
                            type="text" value={formData.name}
                            onChange={e => set("name", e.target.value)}
                            placeholder="Enter project name"
                            className="input" required
                        />
                    </Field>

                    <Field label="Description">
                        <textarea
                            value={formData.description}
                            onChange={e => set("description", e.target.value)}
                            placeholder="Describe your project..."
                            className="input"
                            style={{ height: "5rem", resize: "vertical" }}
                        />
                    </Field>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                        <Field label="Status">
                            <select value={formData.status} onChange={e => set("status", e.target.value)} className="input">
                                <option value="PLANNING">Planning</option>
                                <option value="ACTIVE">Active</option>
                                <option value="COMPLETED">Completed</option>
                                <option value="ON_HOLD">On Hold</option>
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
                            <input type="date" value={formData.start_date} onChange={e => set("start_date", e.target.value)} className="input" />
                        </Field>
                        <Field label="End Date">
                            <input
                                type="date" value={formData.end_date}
                                onChange={e => set("end_date", e.target.value)}
                                min={formData.start_date ? new Date(formData.start_date).toISOString().split('T')[0] : undefined}
                                className="input"
                            />
                        </Field>
                    </div>

                    <Field label="Project Lead">
                        <select
                            value={formData.team_lead}
                            onChange={e => set("team_lead", e.target.value)}
                            className="input"
                        >
                            <option value="">No lead</option>
                            {currentWorkspace?.members?.map(m => (
                                <option key={m.user.email} value={m.user.email}>{m.user.email}</option>
                            ))}
                        </select>
                    </Field>

                    <Field label="Team Members">
                        <select
                            className="input"
                            onChange={e => {
                                if (e.target.value && !formData.team_members.includes(e.target.value)) {
                                    set("team_members", [...formData.team_members, e.target.value])
                                }
                            }}
                        >
                            <option value="">Add team member...</option>
                            {currentWorkspace?.members
                                ?.filter(m => !formData.team_members.includes(m.user.email))
                                .map(m => (
                                    <option key={m.user.email} value={m.user.email}>{m.user.email}</option>
                                ))}
                        </select>
                        {formData.team_members.length > 0 && (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.375rem", marginTop: "0.5rem" }}>
                                {formData.team_members.map(email => (
                                    <span key={email} style={{
                                        display: "inline-flex", alignItems: "center", gap: "0.25rem",
                                        background: "var(--accent-muted)", color: "var(--accent)",
                                        border: "1px solid var(--border-accent)",
                                        borderRadius: "var(--radius-full)",
                                        fontSize: "0.7rem", fontWeight: 500,
                                        padding: "0.2rem 0.5rem 0.2rem 0.625rem"
                                    }}>
                                        {email}
                                        <button
                                            type="button" onClick={() => removeTeamMember(email)}
                                            style={{ background: "none", border: "none", cursor: "pointer", color: "var(--accent)", lineHeight: 1, padding: 0 }}
                                        >
                                            <X size={11} />
                                        </button>
                                    </span>
                                ))}
                            </div>
                        )}
                    </Field>

                    {/* Actions */}
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.625rem", paddingTop: "0.5rem", borderTop: "1px solid var(--border)" }}>
                        <button type="button" onClick={() => setIsDialogOpen(false)} className="btn btn-secondary btn-sm">
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting || !currentWorkspace}
                            className="btn btn-primary btn-sm"
                        >
                            {isSubmitting ? "Creating..." : "Create Project"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    )
}

const Field = ({ label, children }) => (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
        <label style={{ fontSize: "0.75rem", fontWeight: 500, color: "var(--fg-muted)" }}>{label}</label>
        {children}
    </div>
)

export default CreateProjectDialog