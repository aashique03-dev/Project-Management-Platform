import { useEffect, useState } from "react";
import { GitCommit, MessageSquare, Clock, Bug, Zap, Square } from "lucide-react";
import { format } from "date-fns";
import { useSelector } from "react-redux";

const typeIcons = {
    BUG:         { icon: Bug,          color: "#f87171" },
    FEATURE:     { icon: Zap,          color: "#60a5fa" },
    TASK:        { icon: Square,       color: "#34d399" },
    IMPROVEMENT: { icon: MessageSquare,color: "#fbbf24" },
    OTHER:       { icon: GitCommit,    color: "#c084fc" },
}

const statusBadgeClass = {
    todo:        "badge-todo",
    in_progress: "badge-in-progress",
    done:        "badge-done",
}

const statusLabel = {
    todo:        "To Do",
    in_progress: "In Progress",
    done:        "Done",
}

const RecentActivity = () => {
    const [tasks, setTasks] = useState([])
    const { currentWorkspace } = useSelector(state => state.workspace)

    useEffect(() => {
        if (!currentWorkspace) return
        const all = currentWorkspace.projects.flatMap(p => p.tasks)
        setTasks(all)
    }, [currentWorkspace])

    return (
        <div style={{
            background: "var(--card)", backdropFilter: "blur(8px)",
            border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
            overflow: "hidden"
        }}>
            <div style={{ padding: "1rem 1.25rem", borderBottom: "1px solid var(--border)" }}>
                <h2 style={{
                    fontFamily: "'Space Grotesk', sans-serif",
                    fontWeight: 600, fontSize: "0.9rem",
                    letterSpacing: "-0.01em", color: "var(--fg)"
                }}>
                    Recent Activity
                </h2>
            </div>

            {tasks.length === 0 ? (
                <div style={{ padding: "4rem 2rem", textAlign: "center" }}>
                    <div style={{
                        width: 56, height: 56, borderRadius: "var(--radius-full)",
                        background: "var(--bg-elevated)", border: "1px solid var(--border)",
                        display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 1rem"
                    }}>
                        <Clock size={22} strokeWidth={1} style={{ color: "var(--fg-muted)" }} />
                    </div>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>No recent activity</p>
                </div>
            ) : (
                <div>
                    {tasks.map(task => {
                        const taskId = task._id || task.id
                        const typeInfo = typeIcons[task.type] || typeIcons.OTHER
                        const TypeIcon = typeInfo.icon
                        const badgeCls = statusBadgeClass[task.status] || "badge-todo"

                        return (
                            <div key={taskId} style={{
                                display: "flex", alignItems: "flex-start", gap: "0.875rem",
                                padding: "0.875rem 1.25rem",
                                borderBottom: "1px solid var(--border)",
                                transition: "background 200ms"
                            }}
                                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                            >
                                <div style={{
                                    width: 32, height: 32, borderRadius: "var(--radius-md)",
                                    background: "var(--bg-elevated)", flexShrink: 0,
                                    display: "flex", alignItems: "center", justifyContent: "center"
                                }}>
                                    <TypeIcon size={14} strokeWidth={1.5} style={{ color: typeInfo.color }} />
                                </div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "0.5rem", marginBottom: "0.25rem" }}>
                                        <h4 style={{ fontSize: "0.85rem", fontWeight: 500, color: "var(--fg)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                            {task.title}
                                        </h4>
                                        <span className={`badge ${badgeCls}`} style={{ flexShrink: 0 }}>
                                            {statusLabel[task.status] || task.status}
                                        </span>
                                    </div>
                                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                                        {task.type && (
                                            <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                                {task.type.toLowerCase()}
                                            </span>
                                        )}
                                        {task.assignee?.name && (
                                            <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                                                {task.assignee.name}
                                            </span>
                                        )}
                                        {task.updatedAt && !isNaN(new Date(task.updatedAt)) && (
                                            <span style={{ fontSize: "0.7rem", color: "var(--fg-subtle)", marginLeft: "auto" }}>
                                                {format(new Date(task.updatedAt), "MMM d, h:mm a")}
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}

export default RecentActivity