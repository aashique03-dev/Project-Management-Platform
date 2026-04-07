import { useState } from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';
import { ChevronRight, Settings, Kanban, BarChart2, Calendar, ArrowRight } from 'lucide-react';
import { useSelector } from 'react-redux';

const getSubItems = (projectId) => [
    { title: 'Tasks',     icon: Kanban,   url: `/projectsDetail?id=${projectId}&tab=tasks`     },
    { title: 'Analytics', icon: BarChart2, url: `/projectsDetail?id=${projectId}&tab=analytics` },
    { title: 'Calendar',  icon: Calendar,  url: `/projectsDetail?id=${projectId}&tab=calendar`  },
    { title: 'Settings',  icon: Settings,  url: `/projectsDetail?id=${projectId}&tab=settings`  },
];

const ProjectSidebar = () => {
    const location = useLocation();
    const [searchParams] = useSearchParams();
    const [expanded, setExpanded] = useState(new Set());

    const projects = useSelector(state => state?.workspace?.currentWorkspace?.projects || []);

    const toggle = (id) => {
        const next = new Set(expanded);
        next.has(id) ? next.delete(id) : next.add(id);
        setExpanded(next);
    };

    return (
        <div>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.375rem 0.75rem", marginBottom: "0.25rem" }}>
                <span style={{
                    fontSize: "0.65rem", fontWeight: 600,
                    color: "var(--fg-muted)", textTransform: "uppercase",
                    letterSpacing: "0.08em", fontFamily: "'JetBrains Mono', monospace"
                }}>
                    Projects
                </span>
                <Link to="/projects">
                    <button className="btn btn-ghost btn-icon" style={{ width: 22, height: 22, padding: 0 }} aria-label="All projects">
                        <ArrowRight size={12} strokeWidth={1.5} />
                    </button>
                </Link>
            </div>

            {/* Project list */}
            <div style={{ display: "flex", flexDirection: "column", gap: "0.125rem" }}>
                {projects.map(project => {
                    const projectId = project._id || project.id;
                    const isExpanded = expanded.has(projectId);
                    const subItems = getSubItems(projectId);

                    return (
                        <div key={projectId}>
                            <button
                                onClick={() => toggle(projectId)}
                                style={{
                                    width: "100%", display: "flex", alignItems: "center", gap: "0.5rem",
                                    padding: "0.4rem 0.75rem",
                                    borderRadius: "var(--radius-md)",
                                    background: "transparent", border: "none", cursor: "pointer",
                                    transition: "background 200ms", textAlign: "left"
                                }}
                                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                            >
                                <ChevronRight size={12} strokeWidth={1.5} style={{
                                    color: "var(--fg-muted)", flexShrink: 0,
                                    transform: isExpanded ? "rotate(90deg)" : "rotate(0)",
                                    transition: "transform 200ms"
                                }} />
                                <div style={{
                                    width: 6, height: 6, borderRadius: "50%",
                                    background: "var(--accent)", flexShrink: 0, opacity: 0.7
                                }} />
                                <span style={{
                                    fontSize: "0.8rem", color: "var(--fg-muted)",
                                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1
                                }}>
                                    {project.name}
                                </span>
                            </button>

                            {isExpanded && (
                                <div style={{ marginLeft: "1.375rem", display: "flex", flexDirection: "column", gap: "0.125rem", marginTop: "0.125rem" }}>
                                    {subItems.map(item => {
                                        const isActive =
                                            location.pathname === '/projectsDetail' &&
                                            searchParams.get('id') === projectId &&
                                            searchParams.get('tab') === item.title.toLowerCase();

                                        return (
                                            <Link
                                                key={item.title}
                                                to={item.url}
                                                style={{
                                                    display: "flex", alignItems: "center", gap: "0.5rem",
                                                    padding: "0.375rem 0.75rem",
                                                    borderRadius: "var(--radius-md)",
                                                    textDecoration: "none", transition: "all 200ms",
                                                    fontSize: "0.75rem",
                                                    background: isActive ? "var(--accent-muted)" : "transparent",
                                                    color: isActive ? "var(--accent)" : "var(--fg-muted)"
                                                }}
                                                onMouseEnter={e => {
                                                    if (!isActive) {
                                                        e.currentTarget.style.background = "rgba(255,255,255,0.04)"
                                                        e.currentTarget.style.color = "var(--fg)"
                                                    }
                                                }}
                                                onMouseLeave={e => {
                                                    if (!isActive) {
                                                        e.currentTarget.style.background = "transparent"
                                                        e.currentTarget.style.color = "var(--fg-muted)"
                                                    }
                                                }}
                                            >
                                                <item.icon size={12} strokeWidth={1.5} style={{ flexShrink: 0 }} />
                                                {item.title}
                                            </Link>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default ProjectSidebar;