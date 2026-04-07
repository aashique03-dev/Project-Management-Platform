import { useState, useRef, useEffect } from 'react'
import { SearchIcon, PanelLeft, Moon, Sun, LogOut, User, ChevronDown, Zap } from 'lucide-react'
import { useDispatch, useSelector } from 'react-redux'
import { toggleTheme } from '../features/themeSlice'
import { logoutUser } from '../features/authSlice'
import { resetWorkspace } from '../features/workspaceSlice'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'

const Navbar = ({ setIsSidebarOpen }) => {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const user = useSelector((state) => state.auth?.user)
    const displayName = user?.fullName || user?.name || user?.username || user?.email?.split("@")[0] || "User"

    const [dropdownOpen, setDropdownOpen] = useState(false)
    const dropdownRef = useRef(null)

    useEffect(() => {
        const handler = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setDropdownOpen(false)
            }
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [])

    const handleLogout = async () => {
        setDropdownOpen(false)
        await dispatch(logoutUser())
        dispatch(resetWorkspace())
        toast.success('Logged out successfully')
        navigate('/landing')
    }

    const getInitials = (name) => {
        if (!name) return 'U'
        return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)
    }

    return (
        <nav style={{
            background: "rgba(10, 10, 15, 0.85)",
            backdropFilter: "blur(12px)",
            WebkitBackdropFilter: "blur(12px)",
            borderBottom: "1px solid var(--border)",
            padding: "0 1.5rem",
            height: "3.5rem",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexShrink: 0,
            position: "sticky",
            top: 0,
            zIndex: 10
        }}>
            {/* Left */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flex: 1 }}>
                <button
                    onClick={() => setIsSidebarOpen(prev => !prev)}
                    className="btn btn-ghost btn-icon"
                    style={{ display: "none" }}
                    id="sidebar-toggle"
                    aria-label="Toggle sidebar"
                >
                    <PanelLeft size={18} strokeWidth={1.5} />
                </button>

                {/* Search */}
                <div style={{ position: "relative", maxWidth: "22rem", flex: 1 }}>
                    <SearchIcon
                        size={14} strokeWidth={1.5}
                        style={{
                            position: "absolute", left: "0.75rem", top: "50%",
                            transform: "translateY(-50%)", color: "var(--fg-muted)"
                        }}
                    />
                    <input
                        type="text"
                        placeholder="Search projects, tasks..."
                        className="input"
                        style={{
                            paddingLeft: "2.25rem",
                            height: "2.25rem",
                            fontSize: "0.8rem",
                            background: "rgba(26, 26, 36, 0.5)"
                        }}
                    />
                </div>
            </div>

            {/* Right */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                {/* User dropdown */}
                <div style={{ position: "relative" }} ref={dropdownRef}>
                    <button
                        onClick={() => setDropdownOpen(prev => !prev)}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            padding: "0.375rem 0.625rem",
                            borderRadius: "var(--radius-md)",
                            border: "1px solid var(--border)",
                            background: "transparent",
                            cursor: "pointer",
                            transition: "all 200ms ease-out"
                        }}
                        onMouseEnter={e => {
                            e.currentTarget.style.background = "rgba(255,255,255,0.05)"
                            e.currentTarget.style.borderColor = "var(--border-hover)"
                        }}
                        onMouseLeave={e => {
                            e.currentTarget.style.background = "transparent"
                            e.currentTarget.style.borderColor = "var(--border)"
                        }}
                    >
                        {/* Avatar */}
                        <div style={{
                            width: 28, height: 28, borderRadius: "var(--radius-full)",
                            background: "linear-gradient(135deg, var(--accent), #D97706)",
                            display: "flex", alignItems: "center", justifyContent: "center",
                            fontSize: "0.65rem", fontWeight: 700, color: "var(--accent-fg)",
                            flexShrink: 0
                        }}>
                            {getInitials(displayName)}
                        </div>
                        <span style={{
                            fontSize: "0.8rem", fontWeight: 500, color: "var(--fg)",
                            maxWidth: "8rem", overflow: "hidden", textOverflow: "ellipsis",
                            whiteSpace: "nowrap"
                        }}>
                            {displayName}
                        </span>
                        <ChevronDown
                            size={13} strokeWidth={2}
                            style={{
                                color: "var(--fg-muted)",
                                transform: dropdownOpen ? "rotate(180deg)" : "rotate(0)",
                                transition: "transform 200ms"
                            }}
                        />
                    </button>

                    {dropdownOpen && (
                        <div style={{
                            position: "absolute", right: 0, top: "calc(100% + 0.5rem)",
                            width: "15rem",
                            background: "var(--bg-alt)",
                            border: "1px solid var(--border)",
                            borderRadius: "var(--radius-lg)",
                            boxShadow: "var(--shadow-lg)",
                            zIndex: 50,
                            overflow: "hidden",
                            animation: "slideUp 150ms ease-out"
                        }}>
                            {/* User info */}
                            <div style={{
                                padding: "0.875rem 1rem",
                                borderBottom: "1px solid var(--border)"
                            }}>
                                <p style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--fg)", marginBottom: "0.125rem" }}>
                                    {displayName}
                                </p>
                                <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", overflow: "hidden", textOverflow: "ellipsis" }}>
                                    {user?.email || ''}
                                </p>
                            </div>

                            <div style={{ padding: "0.375rem" }}>
                                <DropdownItem icon={User} label="Profile" onClick={() => setDropdownOpen(false)} />
                                <DropdownItem
                                    icon={LogOut} label="Sign out"
                                    onClick={handleLogout}
                                    danger
                                />
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Mobile sidebar toggle */}
            <style>{`
                @media (max-width: 640px) {
                    #sidebar-toggle { display: flex !important; }
                }
            `}</style>
        </nav>
    )
}

const DropdownItem = ({ icon: Icon, label, onClick, danger }) => (
    <button
        onClick={onClick}
        style={{
            width: "100%", display: "flex", alignItems: "center", gap: "0.625rem",
            padding: "0.5rem 0.75rem", borderRadius: "var(--radius-md)",
            background: "transparent", border: "none", cursor: "pointer",
            fontSize: "0.875rem", fontWeight: 400,
            color: danger ? "#f87171" : "var(--fg)",
            transition: "background 150ms ease-out",
            textAlign: "left"
        }}
        onMouseEnter={e => e.currentTarget.style.background = danger ? "rgba(239,68,68,0.1)" : "rgba(255,255,255,0.05)"}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
        <Icon size={15} strokeWidth={1.5} style={{ color: danger ? "#f87171" : "var(--fg-muted)" }} />
        {label}
    </button>
)

export default Navbar