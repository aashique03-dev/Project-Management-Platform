import { useEffect, useState } from 'react';
import { CheckSquare, ChevronDown, ChevronRight } from 'lucide-react';
import { useSelector } from 'react-redux';
import { Link } from 'react-router-dom';

const statusDot = {
    DONE:        "#34d399",
    IN_PROGRESS: "#fbbf24",
    TODO:        "#71717a",
}

function MyTasksSidebar() {
    const user = { id: 'user_1' }
    const { currentWorkspace } = useSelector(state => state.workspace)
    const [showMyTasks, setShowMyTasks] = useState(false)
    const [myTasks, setMyTasks] = useState([])

    useEffect(() => {
        const userId = user?.id || ''
        if (!userId || !currentWorkspace) return
        const tasks = currentWorkspace.projects.flatMap(p =>
            p.tasks.filter(t => t?.assignee?.id === userId)
        )
        setMyTasks(tasks)
    }, [currentWorkspace])

    return (
        <div style={{ marginBottom: "0.5rem" }}>
            <button
                onClick={() => setShowMyTasks(p => !p)}
                style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    width: "100%", padding: "0.5rem 0.75rem",
                    borderRadius: "var(--radius-md)",
                    background: "transparent", border: "none", cursor: "pointer",
                    transition: "background 200ms"
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <CheckSquare size={14} strokeWidth={1.5} style={{ color: "var(--fg-muted)" }} />
                    <span style={{ fontSize: "0.8rem", fontWeight: 500, color: "var(--fg-muted)" }}>My Tasks</span>
                    <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: "0.65rem", fontWeight: 600,
                        background: "var(--bg-elevated)", color: "var(--fg-muted)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius-full)", padding: "0 0.375rem",
                        lineHeight: "1.4rem"
                    }}>
                        {myTasks.length}
                    </span>
                </div>
                {showMyTasks
                    ? <ChevronDown size={13} strokeWidth={1.5} style={{ color: "var(--fg-muted)" }} />
                    : <ChevronRight size={13} strokeWidth={1.5} style={{ color: "var(--fg-muted)" }} />
                }
            </button>

            {showMyTasks && (
                <div style={{ paddingLeft: "0.625rem", marginTop: "0.25rem", display: "flex", flexDirection: "column", gap: "0.125rem" }}>
                    {myTasks.length === 0 ? (
                        <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", padding: "0.5rem 0.75rem", textAlign: "center" }}>
                            No tasks assigned
                        </p>
                    ) : (
                        myTasks.map((task, i) => (
                            <Link
                                key={i}
                                to={`/taskDetails?projectId=${task.projectId}&taskId=${task.id}`}
                                style={{
                                    display: "flex", alignItems: "center", gap: "0.5rem",
                                    padding: "0.375rem 0.75rem",
                                    borderRadius: "var(--radius-md)",
                                    textDecoration: "none", transition: "background 200ms"
                                }}
                                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                            >
                                <div style={{
                                    width: 6, height: 6, borderRadius: "50%", flexShrink: 0,
                                    background: statusDot[task.status] || "#71717a"
                                }} />
                                <span style={{
                                    fontSize: "0.78rem", color: "var(--fg-muted)",
                                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                                }}>
                                    {task.title}
                                </span>
                            </Link>
                        ))
                    )}
                </div>
            )}
        </div>
    )
}

export default MyTasksSidebar