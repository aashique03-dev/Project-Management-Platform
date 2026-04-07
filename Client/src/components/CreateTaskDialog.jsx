import { useState } from "react";
import { Calendar, X } from "lucide-react";
import { useSelector, useDispatch } from "react-redux";
import { format } from "date-fns";
import { createTask } from "../features/workspaceSlice";

export default function CreateTaskDialog({ showCreateTask, setShowCreateTask, projectId }) {
    const dispatch = useDispatch()
    const currentWorkspace = useSelector(state => state.workspace?.currentWorkspace || null)
    const project = currentWorkspace?.projects.find(p => p._id === projectId || p.id === projectId)
    const teamMembers = Array.isArray(project?.members) ? project.members : []

    const [isSubmitting, setIsSubmitting] = useState(false)
    const [formData, setFormData] = useState({
        title: "", description: "", type: "TASK",
        status: "todo", priority: "MEDIUM", assigneeId: "", due_date: ""
    })

    const set = (key, val) => setFormData(prev => ({ ...prev, [key]: val }))

    const handleSubmit = async (e) => {
        e.preventDefault()
        setIsSubmitting(true)
        try {
            await dispatch(createTask({ ...formData, projectId })).unwrap()
            setShowCreateTask(false)
        } catch (err) {
            console.error(err)
        } finally {
            setIsSubmitting(false)
        }
    }

    if (!showCreateTask) return null

    return (
        <div className="overlay" onClick={e => e.target === e.currentTarget && setShowCreateTask(false)}>
            <div className="dialog">
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                    <h2 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontWeight: 700, fontSize: "1.1rem",
                        letterSpacing: "-0.02em", color: "var(--fg)"
                    }}>
                        Create New Task
                    </h2>
                    <button onClick={() => setShowCreateTask(false)} className="btn btn-ghost btn-icon">
                        <X size={16} strokeWidth={1.5} />
                    </button>
                </div>

                <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0.875rem" }}>
                    <Field label="Title">
                        <input
                            value={formData.title}
                            onChange={e => set("title", e.target.value)}
                            placeholder="Task title"
                            className="input" required
                        />
                    </Field>

                    <Field label="Description">
                        <textarea
                            value={formData.description}
                            onChange={e => set("description", e.target.value)}
                            placeholder="Describe the task..."
                            className="input"
                            style={{ height: "5rem", resize: "vertical" }}
                        />
                    </Field>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                        <Field label="Type">
                            <select value={formData.type} onChange={e => set("type", e.target.value)} className="input">
                                <option value="TASK">Task</option>
                                <option value="BUG">Bug</option>
                                <option value="FEATURE">Feature</option>
                                <option value="IMPROVEMENT">Improvement</option>
                                <option value="OTHER">Other</option>
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
                        <Field label="Assignee">
                            <select value={formData.assigneeId} onChange={e => set("assigneeId", e.target.value)} className="input">
                                <option value="">Unassigned</option>
                                {teamMembers.map(m => (
                                    <option key={m?.user.id} value={m?.user.id}>{m?.user.email}</option>
                                ))}
                            </select>
                        </Field>
                        <Field label="Status">
                            <select value={formData.status} onChange={e => set("status", e.target.value)} className="input">
                                <option value="todo">To Do</option>
                                <option value="in_progress">In Progress</option>
                                <option value="done">Done</option>
                            </select>
                        </Field>
                    </div>

                    <Field label="Due Date">
                        <div style={{ position: "relative" }}>
                            <Calendar size={14} strokeWidth={1.5} style={{
                                position: "absolute", left: "0.75rem", top: "50%",
                                transform: "translateY(-50%)", color: "var(--fg-muted)"
                            }} />
                            <input
                                type="date"
                                value={formData.due_date}
                                onChange={e => set("due_date", e.target.value)}
                                min={new Date().toISOString().split('T')[0]}
                                className="input"
                                style={{ paddingLeft: "2.25rem" }}
                            />
                        </div>
                        {formData.due_date && (
                            <p style={{ fontSize: "0.7rem", color: "var(--fg-muted)", marginTop: "0.25rem", fontFamily: "'JetBrains Mono', monospace" }}>
                                {format(new Date(formData.due_date), "PPP")}
                            </p>
                        )}
                    </Field>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.625rem", paddingTop: "0.5rem", borderTop: "1px solid var(--border)" }}>
                        <button type="button" onClick={() => setShowCreateTask(false)} className="btn btn-secondary btn-sm">
                            Cancel
                        </button>
                        <button type="submit" disabled={isSubmitting} className="btn btn-primary btn-sm">
                            {isSubmitting ? "Creating..." : "Create Task"}
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