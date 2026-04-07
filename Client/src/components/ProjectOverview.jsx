// ProjectOverview.jsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Calendar, Users, FolderOpen } from "lucide-react";
import { format } from "date-fns";
import { useSelector } from "react-redux";
import CreateProjectDialog from "./CreateProjectDialog";

const statusMap = {
    PLANNING:  { label: "Planning",  cls: "badge-planning"  },
    ACTIVE:    { label: "Active",    cls: "badge-active"    },
    ON_HOLD:   { label: "On Hold",   cls: "badge-on-hold"   },
    COMPLETED: { label: "Completed", cls: "badge-completed" },
    CANCELLED: { label: "Cancelled", cls: "badge-cancelled" },
}

export const ProjectOverview = () => {
    const currentWorkspace = useSelector(state => state?.workspace?.currentWorkspace || null)
    const [isDialogOpen, setIsDialogOpen] = useState(false)
    const [projects, setProjects] = useState([])

    useEffect(() => {
        setProjects(currentWorkspace?.projects || [])
    }, [currentWorkspace])

    if (!currentWorkspace) return null

    return (
        <div style={{
            background: "var(--card)", backdropFilter: "blur(8px)",
            border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
            overflow: "hidden"
        }}>
            <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "1rem 1.25rem", borderBottom: "1px solid var(--border)"
            }}>
                <h2 style={{
                    fontFamily: "'Space Grotesk', sans-serif",
                    fontWeight: 600, fontSize: "0.9rem",
                    letterSpacing: "-0.01em", color: "var(--fg)"
                }}>
                    Project Overview
                </h2>
                <Link to="/projects" style={{
                    display: "flex", alignItems: "center", gap: "0.25rem",
                    fontSize: "0.75rem", color: "var(--fg-muted)", textDecoration: "none",
                    transition: "color 200ms"
                }}
                    onMouseEnter={e => e.currentTarget.style.color = "var(--fg)"}
                    onMouseLeave={e => e.currentTarget.style.color = "var(--fg-muted)"}
                >
                    View all <ArrowRight size={13} strokeWidth={1.5} />
                </Link>
            </div>

            {projects.length === 0 ? (
                <div style={{ padding: "4rem 2rem", textAlign: "center" }}>
                    <div style={{
                        width: 56, height: 56, borderRadius: "var(--radius-full)",
                        background: "var(--bg-elevated)", border: "1px solid var(--border)",
                        display: "flex", alignItems: "center", justifyContent: "center",
                        margin: "0 auto 1rem"
                    }}>
                        <FolderOpen size={22} strokeWidth={1} style={{ color: "var(--fg-muted)" }} />
                    </div>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)", marginBottom: "1rem" }}>
                        No projects yet
                    </p>
                    <button onClick={() => setIsDialogOpen(true)} className="btn btn-primary btn-sm">
                        Create your first project
                    </button>
                    <CreateProjectDialog isDialogOpen={isDialogOpen} setIsDialogOpen={setIsDialogOpen} />
                </div>
            ) : (
                <div>
                    {projects.slice(0, 5).map(project => {
                        const projectId = project._id || project.id
                        const status = statusMap[project.status]
                        return (
                            <Link key={projectId} to={`/projectsDetail?id=${projectId}&tab=tasks`}
                                style={{
                                    display: "block", padding: "1rem 1.25rem",
                                    borderBottom: "1px solid var(--border)",
                                    textDecoration: "none", transition: "background 200ms"
                                }}
                                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                            >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "0.5rem", marginBottom: "0.625rem" }}>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <h3 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "0.85rem", color: "var(--fg)", marginBottom: "0.25rem", lineHeight: 1.3 }}>
                                            {project.name}
                                        </h3>
                                        <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                            {project.description || 'No description'}
                                        </p>
                                    </div>
                                    {status && <span className={`badge ${status.cls}`}>{status.label}</span>}
                                </div>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.875rem", marginBottom: "0.625rem" }}>
                                    {project.members?.length > 0 && (
                                        <span style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                                            <Users size={11} strokeWidth={1.5} /> {project.members.length}
                                        </span>
                                    )}
                                    {project.end_date && (
                                        <span style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                                            <Calendar size={11} strokeWidth={1.5} /> {format(new Date(project.end_date), "MMM d")}
                                        </span>
                                    )}
                                </div>
                                <div>
                                    <div className="progress-track">
                                        <div className="progress-fill" style={{ width: `${project.progress || 0}%` }} />
                                    </div>
                                </div>
                            </Link>
                        )
                    })}
                </div>
            )}
        </div>
    )
}

export default ProjectOverview