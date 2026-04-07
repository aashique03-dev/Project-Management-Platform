// TasksSummary.jsx
import { useEffect, useState } from "react";
import { ArrowRight, Clock, AlertTriangle, User } from "lucide-react";
import { useSelector } from "react-redux";

export function TasksSummary() {
    const { currentWorkspace } = useSelector(state => state.workspace)
    const user = { id: 'user_1' }
    const [tasks, setTasks] = useState([])

    useEffect(() => {
        if (currentWorkspace) {
            setTasks(currentWorkspace.projects.flatMap(p => p.tasks))
        }
    }, [currentWorkspace])

    const myTasks        = tasks.filter(t => t.assigneeId === user.id)
    const overdueTasks   = tasks.filter(t => t.due_date && new Date(t.due_date) < new Date() && t.status !== 'done')
    const inProgressTasks = tasks.filter(t => t.status === 'in_progress')

    const cards = [
        { title: "My Tasks",    count: myTasks.length,         icon: User,          items: myTasks.slice(0, 3),         color: "#34d399", bg: "rgba(52,211,153,0.1)" },
        { title: "Overdue",     count: overdueTasks.length,    icon: AlertTriangle, items: overdueTasks.slice(0, 3),    color: "#f87171", bg: "rgba(239,68,68,0.1)"  },
        { title: "In Progress", count: inProgressTasks.length, icon: Clock,         items: inProgressTasks.slice(0, 3), color: "#60a5fa", bg: "rgba(96,165,250,0.1)" },
    ]

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {cards.map(({ title, count, icon: Icon, items, color, bg }) => (
                <div key={title} style={{
                    background: "var(--card)", backdropFilter: "blur(8px)",
                    border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                    overflow: "hidden"
                }}>
                    <div style={{
                        display: "flex", alignItems: "center", gap: "0.75rem",
                        padding: "0.875rem 1rem", borderBottom: "1px solid var(--border)"
                    }}>
                        <div style={{ width: 30, height: 30, borderRadius: "var(--radius-md)", background: bg, display: "flex", alignItems: "center", justifyContent: "center" }}>
                            <Icon size={14} strokeWidth={1.5} style={{ color }} />
                        </div>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flex: 1 }}>
                            <h3 style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--fg)" }}>{title}</h3>
                            <span style={{
                                fontFamily: "'JetBrains Mono', monospace",
                                fontSize: "0.75rem", fontWeight: 600,
                                color, background: bg,
                                border: `1px solid ${color}30`,
                                borderRadius: "var(--radius-full)",
                                padding: "0.1rem 0.5rem"
                            }}>{count}</span>
                        </div>
                    </div>
                    <div style={{ padding: "0.75rem 1rem" }}>
                        {items.length === 0 ? (
                            <p style={{ fontSize: "0.8rem", color: "var(--fg-muted)", textAlign: "center", padding: "0.75rem 0" }}>
                                No {title.toLowerCase()}
                            </p>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                                {items.map(task => (
                                    <div key={task.id || task._id} style={{
                                        padding: "0.625rem 0.75rem",
                                        borderRadius: "var(--radius-md)",
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--border)",
                                        cursor: "pointer", transition: "background 200ms"
                                    }}
                                        onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
                                        onMouseLeave={e => e.currentTarget.style.background = "var(--bg-elevated)"}
                                    >
                                        <h4 style={{ fontSize: "0.8rem", fontWeight: 500, color: "var(--fg)", marginBottom: "0.2rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                            {task.title}
                                        </h4>
                                        <p style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                            {task.type} · {task.priority}
                                        </p>
                                    </div>
                                ))}
                                {count > 3 && (
                                    <button style={{
                                        display: "flex", alignItems: "center", justifyContent: "center", gap: "0.25rem",
                                        width: "100%", fontSize: "0.75rem", color: "var(--fg-muted)",
                                        background: "none", border: "none", cursor: "pointer", padding: "0.25rem",
                                        transition: "color 200ms"
                                    }}
                                        onMouseEnter={e => e.currentTarget.style.color = "var(--fg)"}
                                        onMouseLeave={e => e.currentTarget.style.color = "var(--fg-muted)"}
                                    >
                                        View {count - 3} more <ArrowRight size={12} />
                                    </button>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ))}
        </div>
    )
}

export default TasksSummary