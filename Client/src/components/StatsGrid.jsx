import { FolderOpen, CheckCircle, Users, AlertTriangle } from "lucide-react";
import { useEffect, useState } from "react";
import { useSelector } from "react-redux";

const statConfigs = [
    {
        icon: FolderOpen,
        title: "Total Projects",
        key: "totalProjects",
        subtitleFn: (stats, ws) => `in ${ws?.name || 'workspace'}`,
        accentColor: "#60a5fa",
        bgColor: "rgba(96,165,250,0.1)"
    },
    {
        icon: CheckCircle,
        title: "Completed",
        key: "completedProjects",
        subtitleFn: (stats) => `of ${stats.totalProjects} total`,
        accentColor: "#34d399",
        bgColor: "rgba(52,211,153,0.1)"
    },
    {
        icon: Users,
        title: "My Tasks",
        key: "myTasks",
        subtitleFn: () => "assigned to me",
        accentColor: "#c084fc",
        bgColor: "rgba(192,132,252,0.1)"
    },
    {
        icon: AlertTriangle,
        title: "Overdue",
        key: "overdueIssues",
        subtitleFn: () => "need attention",
        accentColor: "#fbbf24",
        bgColor: "rgba(251,191,36,0.1)"
    },
]

export default function StatsGrid() {
    const currentWorkspace = useSelector(state => state?.workspace?.currentWorkspace || null)
    const [stats, setStats] = useState({
        totalProjects: 0, activeProjects: 0,
        completedProjects: 0, myTasks: 0, overdueIssues: 0
    })

    useEffect(() => {
        if (!currentWorkspace) return
        setStats({
            totalProjects: currentWorkspace.projects.length,
            activeProjects: currentWorkspace.projects.filter(
                p => p.status !== "CANCELLED" && p.status !== "COMPLETED"
            ).length,
            completedProjects: currentWorkspace.projects
                .filter(p => p.status === "COMPLETED")
                .reduce((acc, p) => acc + p.tasks.length, 0),
            myTasks: currentWorkspace.projects.reduce(
                (acc, p) => acc + p.tasks.filter(t => t.assignee?.email === currentWorkspace.owner?.email).length, 0
            ),
            overdueIssues: currentWorkspace.projects.reduce(
                (acc, p) => acc + p.tasks.filter(t => t.due_date < new Date()).length, 0
            )
        })
    }, [currentWorkspace])

    return (
        <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "1rem",
            marginBottom: "1.75rem"
        }} className="stats-grid">
            {statConfigs.map(({ icon: Icon, title, key, subtitleFn, accentColor, bgColor }) => (
                <div key={key} className="stat-card">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div>
                            <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginBottom: "0.625rem", fontWeight: 500 }}>
                                {title}
                            </p>
                            <p style={{
                                fontFamily: "'Space Grotesk', sans-serif",
                                fontSize: "2rem", fontWeight: 700,
                                color: accentColor, lineHeight: 1,
                                letterSpacing: "-0.04em"
                            }}>
                                {stats[key]}
                            </p>
                            <p style={{ fontSize: "0.7rem", color: "var(--fg-subtle)", marginTop: "0.375rem" }}>
                                {subtitleFn(stats, currentWorkspace)}
                            </p>
                        </div>
                        <div style={{
                            width: 36, height: 36, borderRadius: "var(--radius-md)",
                            background: bgColor, display: "flex",
                            alignItems: "center", justifyContent: "center", flexShrink: 0
                        }}>
                            <Icon size={17} strokeWidth={1.5} style={{ color: accentColor }} />
                        </div>
                    </div>
                </div>
            ))}
            <style>{`
                @media (max-width: 900px) {
                    .stats-grid { grid-template-columns: repeat(2, 1fr) !important; }
                }
                @media (max-width: 480px) {
                    .stats-grid { grid-template-columns: 1fr 1fr !important; }
                }
            `}</style>
        </div>
    )
}