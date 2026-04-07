import { useState, useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import { Plus, Search, FolderOpen } from "lucide-react";
import ProjectCard from "../components/ProjectCard";
import CreateProjectDialog from "../components/CreateProjectDialog";
import { fetchProjects } from "../features/workspaceSlice";

export default function Projects() {
    const dispatch = useDispatch()
    const projects = useSelector(state => state?.workspace?.currentWorkspace?.projects || [])

    useEffect(() => { dispatch(fetchProjects()) }, [dispatch])

    const [filteredProjects, setFilteredProjects] = useState([])
    const [searchTerm, setSearchTerm] = useState("")
    const [isDialogOpen, setIsDialogOpen] = useState(false)
    const [filters, setFilters] = useState({ status: "ALL", priority: "ALL" })

    useEffect(() => {
        let filtered = projects
        if (searchTerm) {
            filtered = filtered.filter(p =>
                p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                p.description?.toLowerCase().includes(searchTerm.toLowerCase())
            )
        }
        if (filters.status !== "ALL") filtered = filtered.filter(p => p.status === filters.status)
        if (filters.priority !== "ALL") filtered = filtered.filter(p => p.priority === filters.priority)
        setFilteredProjects(filtered)
    }, [projects, searchTerm, filters])

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
                        Projects
                    </h1>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
                        {projects.length} project{projects.length !== 1 ? 's' : ''} in your workspace
                    </p>
                </div>
                <button onClick={() => setIsDialogOpen(true)} className="btn btn-primary">
                    <Plus size={15} strokeWidth={2.5} /> New Project
                </button>
            </div>

            {/* Filters */}
            <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.75rem" }}>
                <div style={{ position: "relative", flex: 1, minWidth: "180px", maxWidth: "20rem" }}>
                    <Search size={14} strokeWidth={1.5} style={{
                        position: "absolute", left: "0.75rem", top: "50%",
                        transform: "translateY(-50%)", color: "var(--fg-muted)"
                    }} />
                    <input
                        onChange={e => setSearchTerm(e.target.value)}
                        value={searchTerm}
                        className="input"
                        style={{ paddingLeft: "2.25rem" }}
                        placeholder="Search projects..."
                    />
                </div>
                <select
                    value={filters.status}
                    onChange={e => setFilters({ ...filters, status: e.target.value })}
                    className="input"
                    style={{ width: "auto", minWidth: "130px" }}
                >
                    <option value="ALL">All Status</option>
                    <option value="ACTIVE">Active</option>
                    <option value="PLANNING">Planning</option>
                    <option value="COMPLETED">Completed</option>
                    <option value="ON_HOLD">On Hold</option>
                    <option value="CANCELLED">Cancelled</option>
                </select>
                <select
                    value={filters.priority}
                    onChange={e => setFilters({ ...filters, priority: e.target.value })}
                    className="input"
                    style={{ width: "auto", minWidth: "130px" }}
                >
                    <option value="ALL">All Priority</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                </select>
            </div>

            {/* Grid */}
            <div style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: "1rem"
            }} className="projects-grid">
                {filteredProjects.length === 0 ? (
                    <div style={{
                        gridColumn: "1 / -1",
                        textAlign: "center", padding: "5rem 2rem"
                    }}>
                        <div style={{
                            width: 72, height: 72, borderRadius: "var(--radius-full)",
                            background: "var(--bg-elevated)",
                            border: "1px solid var(--border)",
                            display: "flex", alignItems: "center",
                            justifyContent: "center", margin: "0 auto 1.25rem"
                        }}>
                            <FolderOpen size={28} strokeWidth={1} style={{ color: "var(--fg-muted)" }} />
                        </div>
                        <h3 style={{
                            fontFamily: "'Space Grotesk', sans-serif",
                            fontWeight: 600, fontSize: "1rem",
                            color: "var(--fg)", marginBottom: "0.5rem"
                        }}>
                            No projects found
                        </h3>
                        <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)", marginBottom: "1.5rem" }}>
                            {searchTerm ? "Try adjusting your search" : "Create your first project to get started"}
                        </p>
                        <button onClick={() => setIsDialogOpen(true)} className="btn btn-primary btn-sm">
                            <Plus size={13} /> Create Project
                        </button>
                    </div>
                ) : (
                    filteredProjects.map(project => (
                        <ProjectCard key={project._id || project.id} project={project} />
                    ))
                )}
            </div>

            <CreateProjectDialog isDialogOpen={isDialogOpen} setIsDialogOpen={setIsDialogOpen} />

            <style>{`
                @media (max-width: 1024px) { .projects-grid { grid-template-columns: repeat(2, 1fr) !important; } }
                @media (max-width: 640px)  { .projects-grid { grid-template-columns: 1fr !important; } }
            `}</style>
        </div>
    )
}