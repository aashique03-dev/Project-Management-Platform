import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowLeft, Plus, Settings, BarChart3, Calendar, FileStack, Zap } from "lucide-react";
import ProjectAnalytics from "../components/ProjectAnalytics";
import ProjectSettings from "../components/ProjectSettings";
import CreateTaskDialog from "../components/CreateTaskDialog";
import ProjectCalendar from "../components/ProjectCalendar";
import ProjectTasks from "../components/ProjectTasks";
import { fetchProjectTasks } from "../features/workspaceSlice";

const statusMap = {
    PLANNING:  { label: "Planning",  cls: "badge-planning"  },
    ACTIVE:    { label: "Active",    cls: "badge-active"    },
    ON_HOLD:   { label: "On Hold",   cls: "badge-on-hold"   },
    COMPLETED: { label: "Completed", cls: "badge-completed" },
    CANCELLED: { label: "Cancelled", cls: "badge-cancelled" },
}

export default function ProjectDetail() {
    const dispatch = useDispatch()
    const [searchParams, setSearchParams] = useSearchParams()
    const tab = searchParams.get('tab')
    const id = searchParams.get('id')
    const navigate = useNavigate()
    const projects = useSelector(state => state?.workspace?.currentWorkspace?.projects || [])

    const [project, setProject] = useState(null)
    const [tasks, setTasks] = useState([])
    const [showCreateTask, setShowCreateTask] = useState(false)
    const [activeTab, setActiveTab] = useState(tab || "tasks")

    useEffect(() => { if (tab) setActiveTab(tab) }, [tab])
    useEffect(() => { if (id) dispatch(fetchProjectTasks(id)) }, [id, dispatch])
    useEffect(() => {
        if (projects.length > 0) {
            const proj = projects.find(p => p._id === id || p.id === id)
            setProject(proj)
            setTasks(proj?.tasks || [])
        }
    }, [id, projects])

    if (!project) return (
        <div style={{ textAlign: "center", padding: "8rem 2rem" }}>
            <p style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: "2rem", fontWeight: 700,
                color: "var(--fg-muted)", marginBottom: "1.5rem"
            }}>
                Project not found
            </p>
            <button onClick={() => navigate('/projects')} className="btn btn-secondary">
                Back to Projects
            </button>
        </div>
    )

    const status = statusMap[project.status]
    const tabs = [
        { key: "tasks", label: "Tasks", icon: FileStack },
        { key: "calendar", label: "Calendar", icon: Calendar },
        { key: "analytics", label: "Analytics", icon: BarChart3 },
        { key: "settings", label: "Settings", icon: Settings },
    ]

    const infoCards = [
        { label: "Total Tasks", value: tasks.length, color: "var(--fg)" },
        { label: "Completed", value: tasks.filter(t => t.status === "done").length, color: "#34d399" },
        { label: "In Progress", value: tasks.filter(t => t.status === "in_progress" || t.status === "todo").length, color: "#fbbf24" },
        { label: "Members", value: project.members?.length || 0, color: "#60a5fa" },
    ]

    return (
        <div>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap", marginBottom: "1.5rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                    <button
                        onClick={() => navigate('/projects')}
                        className="btn btn-ghost btn-icon"
                        aria-label="Back to projects"
                    >
                        <ArrowLeft size={16} strokeWidth={1.5} />
                    </button>
                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.625rem" }}>
                            <h1 style={{
                                fontFamily: "'Space Grotesk', sans-serif",
                                fontWeight: 700, fontSize: "1.25rem",
                                letterSpacing: "-0.025em", color: "var(--fg)"
                            }}>
                                {project.name}
                            </h1>
                            {status && <span className={`badge ${status.cls}`}>{status.label}</span>}
                        </div>
                        {project.description && (
                            <p style={{ fontSize: "0.8rem", color: "var(--fg-muted)", marginTop: "0.2rem" }}>
                                {project.description}
                            </p>
                        )}
                    </div>
                </div>
                <button onClick={() => setShowCreateTask(true)} className="btn btn-primary">
                    <Plus size={15} strokeWidth={2.5} /> New Task
                </button>
            </div>

            {/* Info Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "0.75rem", marginBottom: "1.75rem" }} className="info-cards">
                {infoCards.map(({ label, value, color }) => (
                    <div key={label} style={{
                        background: "var(--card)",
                        backdropFilter: "blur(8px)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius-lg)",
                        padding: "0.875rem 1rem",
                        display: "flex", alignItems: "center", justifyContent: "space-between"
                    }}>
                        <div>
                            <p style={{ fontSize: "0.7rem", color: "var(--fg-muted)", marginBottom: "0.25rem" }}>{label}</p>
                            <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "1.5rem", fontWeight: 700, color, letterSpacing: "-0.04em" }}>
                                {value}
                            </p>
                        </div>
                        <Zap size={14} strokeWidth={1.5} style={{ color, opacity: 0.6 }} />
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <div style={{
                display: "inline-flex", gap: "0.25rem",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-lg)",
                padding: "0.25rem",
                marginBottom: "1.5rem",
                flexWrap: "wrap"
            }}>
                {tabs.map(t => (
                    <button
                        key={t.key}
                        onClick={() => {
                            setActiveTab(t.key)
                            setSearchParams({ id, tab: t.key })
                        }}
                        className={`tab-btn ${activeTab === t.key ? "active" : ""}`}
                    >
                        <t.icon size={14} strokeWidth={1.5} />
                        {t.label}
                    </button>
                ))}
            </div>

            {/* Tab content */}
            <div>
                {activeTab === "tasks"     && <ProjectTasks tasks={tasks} />}
                {activeTab === "analytics" && <ProjectAnalytics tasks={tasks} project={project} />}
                {activeTab === "calendar"  && <ProjectCalendar tasks={tasks} />}
                {activeTab === "settings"  && <ProjectSettings project={project} />}
            </div>

            {showCreateTask && (
                <CreateTaskDialog showCreateTask={showCreateTask} setShowCreateTask={setShowCreateTask} projectId={id} />
            )}

            <style>{`
                @media (max-width: 768px) {
                    .info-cards { grid-template-columns: repeat(2, 1fr) !important; }
                }
                @media (max-width: 480px) {
                    .info-cards { grid-template-columns: 1fr 1fr !important; }
                }
            `}</style>
        </div>
    )
}