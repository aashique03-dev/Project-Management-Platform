import { Plus } from 'lucide-react'
import { useState } from 'react'
import StatsGrid from '../components/StatsGrid'
import ProjectOverview from '../components/ProjectOverview'
import RecentActivity from '../components/RecentActivity'
import TasksSummary from '../components/TasksSummary'
import CreateProjectDialog from '../components/CreateProjectDialog'
import { useSelector } from 'react-redux'

const Dashboard = () => {
    const user = useSelector(state => state.auth?.user)
    const [isDialogOpen, setIsDialogOpen] = useState(false)

    return (
        <div>
            {/* Header */}
            <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                gap: "1.5rem", flexWrap: "wrap", marginBottom: "2rem"
            }}>
                <div>
                    <p className="section-label">Dashboard</p>
                    <h1 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontSize: "1.75rem", fontWeight: 700,
                        letterSpacing: "-0.03em", color: "var(--fg)",
                        marginBottom: "0.375rem", lineHeight: 1.2
                    }}>
                        Welcome back, {user?.fullName?.split(' ')[0] || 'there'}
                    </h1>
                    <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>
                        Here's what's happening with your projects today.
                    </p>
                </div>

                <button
                    onClick={() => setIsDialogOpen(true)}
                    className="btn btn-primary"
                >
                    <Plus size={15} strokeWidth={2.5} />
                    New Project
                </button>
            </div>

            <StatsGrid />

            <div style={{
                display: "grid",
                gridTemplateColumns: "1fr 20rem",
                gap: "1.5rem",
                alignItems: "start"
            }} className="dashboard-grid">
                <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
                    <ProjectOverview />
                    <RecentActivity />
                </div>
                <TasksSummary />
            </div>

            <CreateProjectDialog isDialogOpen={isDialogOpen} setIsDialogOpen={setIsDialogOpen} />

            <style>{`
                @media (max-width: 1024px) {
                    .dashboard-grid {
                        grid-template-columns: 1fr !important;
                    }
                }
            `}</style>
        </div>
    )
}

export default Dashboard