import { useEffect, useRef } from 'react'
import { NavLink } from 'react-router-dom'
import MyTasksSidebar from './MyTasksSidebar'
import ProjectSidebar from './ProjectsSidebar'
import { FolderOpen, LayoutDashboard, Settings, Users, Zap, Loader2 } from 'lucide-react'
import { useDispatch, useSelector } from 'react-redux'
import { fetchProjects } from '../features/workspaceSlice'

const menuItems = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Projects', href: '/projects', icon: FolderOpen },
    { name: 'Team', href: '/team', icon: Users },
]

const Sidebar = ({ isSidebarOpen, setIsSidebarOpen }) => {
    const dispatch = useDispatch()
    const user = useSelector((state) => state.auth?.user)
    const loading = useSelector((state) => state.workspace.loading)
    const sidebarRef = useRef(null)

    useEffect(() => {
        dispatch(fetchProjects())
    }, [dispatch])

    useEffect(() => {
        const handler = (e) => {
            if (sidebarRef.current && !sidebarRef.current.contains(e.target)) {
                setIsSidebarOpen(false)
            }
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [setIsSidebarOpen])

    return (
        <aside
            ref={sidebarRef}
            style={{
                width: "16rem",
                minWidth: "16rem",
                background: "rgba(18, 18, 26, 0.95)",
                backdropFilter: "blur(12px)",
                WebkitBackdropFilter: "blur(12px)",
                borderRight: "1px solid var(--border)",
                display: "flex",
                flexDirection: "column",
                height: "100vh",
                flexShrink: 0,
                position: "relative",
                zIndex: 20,
                transition: "transform 300ms ease-out"
            }}
            className={`sidebar-root ${isSidebarOpen ? 'sidebar-open' : ''}`}
        >
            {/* Logo / Workspace header */}
            <div style={{
                padding: "1.125rem 1rem",
                borderBottom: "1px solid var(--border)",
                display: "flex", alignItems: "center", gap: "0.625rem"
            }}>
                <div style={{
                    width: 32, height: 32, borderRadius: "var(--radius-md)",
                    background: "linear-gradient(135deg, var(--accent), #D97706)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    flexShrink: 0, boxShadow: "var(--glow-sm)"
                }}>
                    <Zap size={16} color="var(--accent-fg)" strokeWidth={2.5} />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                    <p style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontWeight: 700, fontSize: "0.9rem",
                        letterSpacing: "-0.02em", color: "var(--fg)",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                    }}>
                        ProjectFlow
                    </p>
                    <p style={{
                        fontSize: "0.7rem", color: "var(--fg-muted)",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                        fontFamily: "'JetBrains Mono', monospace"
                    }}>
                        {user?.email || 'Personal workspace'}
                    </p>
                </div>
            </div>

            {/* Nav */}
            <div style={{ flex: 1, overflowY: "auto", padding: "0.75rem 0.625rem" }}
                className="no-scrollbar">

                {/* Main nav items */}
                <div style={{ display: "flex", flexDirection: "column", gap: "0.125rem" }}>
                    {menuItems.map((item) => (
                        <NavLink
                            key={item.name}
                            to={item.href}
                            end={item.href === '/'}
                            style={({ isActive }) => ({
                                display: "flex", alignItems: "center", gap: "0.625rem",
                                padding: "0.5rem 0.75rem",
                                borderRadius: "var(--radius-md)",
                                fontSize: "0.875rem", fontWeight: 450,
                                color: isActive ? "var(--fg)" : "var(--fg-muted)",
                                background: isActive ? "rgba(255,255,255,0.07)" : "transparent",
                                textDecoration: "none",
                                transition: "all 200ms ease-out",
                                border: "none"
                            })}
                            onMouseEnter={e => {
                                if (!e.currentTarget.classList.contains('active-nav'))
                                    e.currentTarget.style.background = "rgba(255,255,255,0.04)"
                            }}
                            onMouseLeave={e => {
                                if (!e.currentTarget.getAttribute('aria-current'))
                                    e.currentTarget.style.background = ""
                            }}
                        >
                            {({ isActive }) => (
                                <>
                                    <item.icon
                                        size={16} strokeWidth={isActive ? 2 : 1.5}
                                        style={{ color: isActive ? "var(--accent)" : "var(--fg-muted)", flexShrink: 0 }}
                                    />
                                    {item.name}
                                </>
                            )}
                        </NavLink>
                    ))}
                    <button
                        style={{
                            display: "flex", alignItems: "center", gap: "0.625rem",
                            width: "100%", padding: "0.5rem 0.75rem",
                            borderRadius: "var(--radius-md)",
                            fontSize: "0.875rem", fontWeight: 450,
                            color: "var(--fg-muted)",
                            background: "transparent", border: "none",
                            cursor: "pointer", textAlign: "left",
                            transition: "all 200ms ease-out"
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                        <Settings size={16} strokeWidth={1.5} style={{ color: "var(--fg-muted)", flexShrink: 0 }} />
                        Settings
                    </button>
                </div>

                {/* Divider */}
                <div style={{ height: "1px", background: "var(--border)", margin: "0.75rem 0" }} />

                {/* Dynamic sections */}
                {loading ? (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "1.5rem 0" }}>
                        <Loader2 size={18} strokeWidth={1.5} style={{ color: "var(--accent)", animation: "spin 0.8s linear infinite" }} />
                    </div>
                ) : (
                    <>
                        <MyTasksSidebar />
                        <ProjectSidebar />
                    </>
                )}
            </div>

            <style>{`
                @media (max-width: 640px) {
                    .sidebar-root {
                        position: absolute;
                        top: 0;
                        left: -16rem;
                        height: 100%;
                        z-index: 50;
                        box-shadow: var(--shadow-lg);
                    }
                    .sidebar-root.sidebar-open {
                        left: 0;
                    }
                }
            `}</style>
        </aside>
    )
}

export default Sidebar