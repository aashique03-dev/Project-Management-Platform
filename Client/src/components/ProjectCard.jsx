import { Link } from "react-router-dom";
import { Calendar, Users } from "lucide-react";
import { format } from "date-fns";

const statusMap = {
    PLANNING:  { label: "Planning",   cls: "badge-planning"  },
    ACTIVE:    { label: "Active",     cls: "badge-active"    },
    ON_HOLD:   { label: "On Hold",    cls: "badge-on-hold"   },
    COMPLETED: { label: "Completed",  cls: "badge-completed" },
    CANCELLED: { label: "Cancelled",  cls: "badge-cancelled" },
}

const priorityMap = {
    LOW:    { label: "Low",    cls: "badge-low"    },
    MEDIUM: { label: "Medium", cls: "badge-medium" },
    HIGH:   { label: "High",   cls: "badge-high"   },
}

const ProjectCard = ({ project }) => {
    const projectId = project._id || project.id
    const status = statusMap[project.status]
    const priority = priorityMap[project.priority]
    const progress = project.progress || 0

    return (
        <Link
            to={`/projectsDetail?id=${projectId}&tab=tasks`}
            style={{
                display: "block",
                padding: "1.25rem",
                background: "var(--card)",
                backdropFilter: "blur(8px)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-lg)",
                textDecoration: "none",
                transition: "all 300ms ease-out",
                position: "relative",
                overflow: "hidden"
            }}
            onMouseEnter={e => {
                e.currentTarget.style.borderColor = "var(--border-hover)"
                e.currentTarget.style.transform = "translateY(-1px)"
                e.currentTarget.style.boxShadow = "var(--shadow-md)"
            }}
            onMouseLeave={e => {
                e.currentTarget.style.borderColor = "var(--border)"
                e.currentTarget.style.transform = "none"
                e.currentTarget.style.boxShadow = "none"
            }}
        >
            {/* Header */}
            <div style={{ marginBottom: "0.875rem" }}>
                <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "0.5rem", marginBottom: "0.5rem" }}>
                    <h3 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontWeight: 600, fontSize: "0.9rem",
                        color: "var(--fg)", letterSpacing: "-0.01em",
                        lineHeight: 1.3, flex: 1
                    }}>
                        {project.name}
                    </h3>
                    {status && <span className={`badge ${status.cls}`}>{status.label}</span>}
                </div>
                <p style={{
                    fontSize: "0.8rem", color: "var(--fg-muted)",
                    lineHeight: 1.55,
                    display: "-webkit-box", WebkitLineClamp: 2,
                    WebkitBoxOrient: "vertical", overflow: "hidden"
                }}>
                    {project.description || "No description provided."}
                </p>
            </div>

            {/* Meta */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.875rem", marginBottom: "1rem" }}>
                {project.members?.length > 0 && (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                        <Users size={12} strokeWidth={1.5} />
                        {project.members.length}
                    </div>
                )}
                {project.end_date && (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                        <Calendar size={12} strokeWidth={1.5} />
                        {format(new Date(project.end_date), "MMM d, yyyy")}
                    </div>
                )}
                {priority && (
                    <span className={`badge ${priority.cls}`} style={{ marginLeft: "auto" }}>
                        {priority.label}
                    </span>
                )}
            </div>

            {/* Progress */}
            <div>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.375rem" }}>
                    <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>Progress</span>
                    <span style={{ fontSize: "0.7rem", color: progress > 0 ? "var(--accent)" : "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace", fontWeight: 500 }}>
                        {progress}%
                    </span>
                </div>
                <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${progress}%` }} />
                </div>
            </div>
        </Link>
    )
}

export default ProjectCard