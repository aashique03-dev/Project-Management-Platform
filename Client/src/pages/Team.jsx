import { useEffect, useState } from "react";
import { Users, Search, UserPlus, Shield, Activity } from "lucide-react";
import InviteMemberDialog from "../components/InviteMemberDialog";
import { useSelector } from "react-redux";

const Team = () => {
    const [tasks, setTasks] = useState([])
    const [searchTerm, setSearchTerm] = useState("")
    const [isDialogOpen, setIsDialogOpen] = useState(false)
    const [users, setUsers] = useState([])
    const currentWorkspace = useSelector(state => state?.workspace?.currentWorkspace || null)
    const projects = currentWorkspace?.projects || []

    const filteredUsers = users.filter(u =>
        u?.user?.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u?.user?.email?.toLowerCase().includes(searchTerm.toLowerCase())
    )

    useEffect(() => {
        setUsers(currentWorkspace?.members || [])
        setTasks(currentWorkspace?.projects?.reduce((acc, p) => [...acc, ...p.tasks], []) || [])
    }, [currentWorkspace])

    const statCards = [
        {
            label: "Total Members", value: users.length,
            icon: Users, color: "#60a5fa", bg: "rgba(96,165,250,0.1)"
        },
        {
            label: "Active Projects",
            value: projects.filter(p => p.status !== "CANCELLED" && p.status !== "COMPLETED").length,
            icon: Activity, color: "#34d399", bg: "rgba(52,211,153,0.1)"
        },
        {
            label: "Total Tasks", value: tasks.length,
            icon: Shield, color: "#c084fc", bg: "rgba(192,132,252,0.1)"
        },
    ]

    return (
        <div>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1.5rem", flexWrap: "wrap", marginBottom: "1.75rem" }}>
                <div>
                    <p className="section-label">Workspace</p>
                    <h1 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontSize: "1.75rem", fontWeight: 700,
                        letterSpacing: "-0.03em", color: "var(--fg)", marginBottom: "0.25rem"
                    }}>
                        Team
                    </h1>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
                        Manage members and their contributions
                    </p>
                </div>
                <button onClick={() => setIsDialogOpen(true)} className="btn btn-primary">
                    <UserPlus size={15} strokeWidth={2} /> Invite Member
                </button>
            </div>

            {/* Stats */}
            <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "1.75rem" }}>
                {statCards.map(({ label, value, icon: Icon, color, bg }) => (
                    <div key={label} className="stat-card" style={{ flex: "1", minWidth: "180px" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1.5rem" }}>
                            <div>
                                <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)", marginBottom: "0.375rem" }}>{label}</p>
                                <p style={{
                                    fontFamily: "'Space Grotesk', sans-serif",
                                    fontSize: "1.75rem", fontWeight: 700,
                                    color, letterSpacing: "-0.04em"
                                }}>{value}</p>
                            </div>
                            <div style={{ width: 38, height: 38, borderRadius: "var(--radius-md)", background: bg, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                                <Icon size={17} strokeWidth={1.5} style={{ color }} />
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Search */}
            <div style={{ position: "relative", maxWidth: "24rem", marginBottom: "1.5rem" }}>
                <Search size={14} strokeWidth={1.5} style={{
                    position: "absolute", left: "0.75rem", top: "50%",
                    transform: "translateY(-50%)", color: "var(--fg-muted)"
                }} />
                <input
                    placeholder="Search members..."
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    className="input"
                    style={{ paddingLeft: "2.25rem" }}
                />
            </div>

            {/* Members */}
            {filteredUsers.length === 0 ? (
                <div style={{ textAlign: "center", padding: "5rem 2rem" }}>
                    <div style={{
                        width: 72, height: 72, borderRadius: "var(--radius-full)",
                        background: "var(--bg-elevated)", border: "1px solid var(--border)",
                        display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 1.25rem"
                    }}>
                        <Users size={28} strokeWidth={1} style={{ color: "var(--fg-muted)" }} />
                    </div>
                    <h3 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "1rem", color: "var(--fg)", marginBottom: "0.5rem" }}>
                        {users.length === 0 ? "No team members yet" : "No members match your search"}
                    </h3>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
                        {users.length === 0 ? "Invite team members to start collaborating" : "Try adjusting your search"}
                    </p>
                </div>
            ) : (
                <>
                    {/* Desktop table */}
                    <div className="table-wrapper" style={{ display: "block" }} id="team-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Member</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredUsers.map(user => (
                                    <tr key={user.id}>
                                        <td>
                                            <div style={{ display: "flex", alignItems: "center", gap: "0.625rem" }}>
                                                <Avatar name={user.user?.name} src={user.user?.image} />
                                                <span style={{ fontWeight: 500, color: "var(--fg)" }}>
                                                    {user.user?.name || "Unknown"}
                                                </span>
                                            </div>
                                        </td>
                                        <td style={{ color: "var(--fg-muted)" }}>{user.user?.email}</td>
                                        <td>
                                            <span className={`badge ${user.role === "ADMIN" ? "badge-active" : "badge-planning"}`}>
                                                {user.role || "Member"}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Mobile cards */}
                    <div id="team-cards" style={{ display: "none", flexDirection: "column", gap: "0.75rem" }}>
                        {filteredUsers.map(user => (
                            <div key={user.id} style={{
                                padding: "1rem", background: "var(--card)",
                                border: "1px solid var(--border)", borderRadius: "var(--radius-lg)"
                            }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem" }}>
                                    <Avatar name={user.user?.name} src={user.user?.image} size={36} />
                                    <div>
                                        <p style={{ fontWeight: 600, color: "var(--fg)", fontSize: "0.9rem" }}>
                                            {user.user?.name || "Unknown"}
                                        </p>
                                        <p style={{ fontSize: "0.75rem", color: "var(--fg-muted)" }}>{user.user?.email}</p>
                                    </div>
                                </div>
                                <span className={`badge ${user.role === "ADMIN" ? "badge-active" : "badge-planning"}`}>
                                    {user.role || "Member"}
                                </span>
                            </div>
                        ))}
                    </div>
                </>
            )}

            <InviteMemberDialog isDialogOpen={isDialogOpen} setIsDialogOpen={setIsDialogOpen} />

            <style>{`
                @media (max-width: 640px) {
                    #team-table { display: none !important; }
                    #team-cards { display: flex !important; }
                }
            `}</style>
        </div>
    )
}

const Avatar = ({ name, src, size = 28 }) => (
    src ? (
        <img src={src} alt={name} style={{
            width: size, height: size, borderRadius: "var(--radius-full)",
            objectFit: "cover", flexShrink: 0, background: "var(--bg-elevated)"
        }} />
    ) : (
        <div style={{
            width: size, height: size, borderRadius: "var(--radius-full)",
            background: "var(--accent-muted)", border: "1px solid var(--border-accent)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: Math.round(size * 0.35) + "px", fontWeight: 700,
            color: "var(--accent)", flexShrink: 0
        }}>
            {name?.[0]?.toUpperCase() || "?"}
        </div>
    )
)

export default Team