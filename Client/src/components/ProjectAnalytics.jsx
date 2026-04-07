import { useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { CheckCircle, Clock, AlertTriangle, Users } from "lucide-react";

const COLORS = ["#F59E0B", "#34d399", "#60a5fa", "#f87171", "#c084fc"];

const priorityColors = {
    LOW:    { bar: "#71717a", text: "#a1a1aa" },
    MEDIUM: { bar: "#F59E0B", text: "#fbbf24" },
    HIGH:   { bar: "#f87171", text: "#f87171" },
};

const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
        <div style={{ background:"#1A1A24", border:"1px solid rgba(255,255,255,0.08)", borderRadius:8, padding:"0.5rem 0.75rem" }}>
            <p style={{ fontSize:"0.75rem", color:"#FAFAFA", fontWeight:600 }}>{label || payload[0]?.name}</p>
            <p style={{ fontSize:"0.75rem", color:"#F59E0B", fontFamily:"'JetBrains Mono',monospace" }}>{payload[0]?.value}</p>
        </div>
    );
};

const ProjectAnalytics = ({ project, tasks }) => {
    const { stats, statusData, typeData, priorityData } = useMemo(() => {
        const now = new Date();
        const stats = { total: tasks.length, completed: 0, inProgress: 0, todo: 0, overdue: 0 };
        const statusMap   = { todo: 0, in_progress: 0, done: 0 };
        const typeMap     = { TASK: 0, BUG: 0, FEATURE: 0, IMPROVEMENT: 0, OTHER: 0 };
        const priorityMap = { LOW: 0, MEDIUM: 0, HIGH: 0 };

        tasks.forEach(t => {
            if (t.status === "done")        stats.completed++;
            if (t.status === "in_progress") stats.inProgress++;
            if (t.status === "todo")        stats.todo++;
            if (new Date(t.dueDate || t.due_date) < now && t.status !== "done") stats.overdue++;
            if (statusMap[t.status]   !== undefined) statusMap[t.status]++;
            if (typeMap[t.type]       !== undefined) typeMap[t.type]++;
            if (priorityMap[t.priority] !== undefined) priorityMap[t.priority]++;
        });

        return {
            stats,
            statusData: Object.entries(statusMap).map(([k,v]) => ({
                name: k.replace(/_/g," ").replace(/\b\w/g,c=>c.toUpperCase()), value: v
            })),
            typeData: Object.entries(typeMap).filter(([,v])=>v>0).map(([k,v])=>({ name:k, value:v })),
            priorityData: Object.entries(priorityMap).map(([k,v]) => ({
                name: k, value: v,
                pct: stats.total > 0 ? Math.round((v/stats.total)*100) : 0
            })),
        };
    }, [tasks]);

    const completionRate = stats.total ? Math.round((stats.completed/stats.total)*100) : 0;

    const metrics = [
        { label:"Completion", value:`${completionRate}%`, icon:CheckCircle, color:"#34d399", bg:"rgba(52,211,153,0.1)"  },
        { label:"In Progress", value:stats.inProgress,    icon:Clock,        color:"#60a5fa", bg:"rgba(96,165,250,0.1)"  },
        { label:"Overdue",    value:stats.overdue,        icon:AlertTriangle, color:"#f87171", bg:"rgba(239,68,68,0.1)"  },
        { label:"Team Size",  value:project?.members?.length||0, icon:Users, color:"#c084fc", bg:"rgba(192,132,252,0.1)" },
    ];

    const cardStyle = {
        background:"rgba(26,26,36,0.6)", backdropFilter:"blur(8px)",
        border:"1px solid rgba(255,255,255,0.07)", borderRadius:12, padding:"1.25rem 1.5rem"
    };

    const axisStyle = { fill:"#52525b", fontSize:11, fontFamily:"'JetBrains Mono',monospace" };

    return (
        <div style={{ display:"flex", flexDirection:"column", gap:"1.25rem" }}>
            {/* Metric cards */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:"0.875rem" }} className="analytics-metrics">
                {metrics.map(({ label, value, icon:Icon, color, bg }) => (
                    <div key={label} style={cardStyle}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
                            <div>
                                <p style={{ fontSize:"0.72rem", color:"var(--fg-muted)", marginBottom:8 }}>{label}</p>
                                <p style={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:"1.75rem", fontWeight:700, color, letterSpacing:"-0.04em" }}>
                                    {value}
                                </p>
                            </div>
                            <div style={{ width:36, height:36, borderRadius:10, background:bg, display:"flex", alignItems:"center", justifyContent:"center" }}>
                                <Icon size={16} strokeWidth={1.5} style={{ color }} />
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Charts row */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"1rem" }} className="analytics-charts">
                {/* Bar chart — Tasks by Status */}
                <div style={cardStyle}>
                    <h3 style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:600, fontSize:"0.875rem", color:"var(--fg)", marginBottom:"1.25rem" }}>
                        Tasks by Status
                    </h3>
                    <ResponsiveContainer width="100%" height={240}>
                        <BarChart data={statusData} barCategoryGap="40%">
                            <XAxis dataKey="name" tick={axisStyle} axisLine={{ stroke:"rgba(255,255,255,0.07)" }} tickLine={false} />
                            <YAxis tick={axisStyle} axisLine={false} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Bar dataKey="value" fill="#F59E0B" radius={[5,5,0,0]} maxBarSize={40} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Pie chart — Tasks by Type */}
                <div style={cardStyle}>
                    <h3 style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:600, fontSize:"0.875rem", color:"var(--fg)", marginBottom:"1.25rem" }}>
                        Tasks by Type
                    </h3>
                    {typeData.length === 0 ? (
                        <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:240, color:"var(--fg-muted)", fontSize:"0.875rem" }}>
                            No data yet
                        </div>
                    ) : (
                        <ResponsiveContainer width="100%" height={240}>
                            <PieChart>
                                <Pie data={typeData} dataKey="value" nameKey="name"
                                    cx="50%" cy="50%" outerRadius={90} innerRadius={40}
                                    label={({ name, value }) => `${name}: ${value}`}
                                    labelLine={{ stroke:"rgba(255,255,255,0.15)" }}
                                >
                                    {typeData.map((_,i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                                </Pie>
                                <Tooltip content={<CustomTooltip />} />
                            </PieChart>
                        </ResponsiveContainer>
                    )}
                </div>
            </div>

            {/* Priority breakdown */}
            <div style={cardStyle}>
                <h3 style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:600, fontSize:"0.875rem", color:"var(--fg)", marginBottom:"1.25rem" }}>
                    Priority Breakdown
                </h3>
                <div style={{ display:"flex", flexDirection:"column", gap:"1rem" }}>
                    {priorityData.map(p => {
                        const pc = priorityColors[p.name] || {};
                        return (
                            <div key={p.name}>
                                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
                                    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                                        <div style={{ width:8, height:8, borderRadius:"50%", background:pc.bar }} />
                                        <span style={{ fontSize:"0.83rem", color:"var(--fg)", textTransform:"capitalize" }}>
                                            {p.name.toLowerCase()}
                                        </span>
                                    </div>
                                    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                                        <span style={{ fontSize:"0.78rem", color:"var(--fg-muted)" }}>{p.value} tasks</span>
                                        <span style={{
                                            fontFamily:"'JetBrains Mono',monospace",
                                            fontSize:"0.7rem", color:pc.text,
                                            background:`${pc.bar}18`,
                                            border:`1px solid ${pc.bar}30`,
                                            borderRadius:9999, padding:"0.1rem 0.45rem"
                                        }}>
                                            {p.pct}%
                                        </span>
                                    </div>
                                </div>
                                <div style={{ height:4, borderRadius:9999, background:"rgba(255,255,255,0.07)", overflow:"hidden" }}>
                                    <div style={{ height:"100%", width:`${p.pct}%`, borderRadius:9999, background:pc.bar, transition:"width 600ms ease-out" }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            <style>{`
                @media (max-width: 900px) { .analytics-metrics { grid-template-columns: repeat(2,1fr) !important; } }
                @media (max-width: 640px) { .analytics-charts  { grid-template-columns: 1fr !important; } }
            `}</style>
        </div>
    );
};

export default ProjectAnalytics;