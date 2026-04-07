import { useState } from "react";
import { format, isSameDay, isBefore, startOfMonth, endOfMonth, eachDayOfInterval, addMonths, subMonths } from "date-fns";
import { Calendar, Clock, User, ChevronLeft, ChevronRight, AlertTriangle } from "lucide-react";

const typeColors = {
    BUG:         { bg: "rgba(239,68,68,0.12)",   color: "#f87171" },
    FEATURE:     { bg: "rgba(96,165,250,0.12)",  color: "#60a5fa" },
    TASK:        { bg: "rgba(52,211,153,0.12)",  color: "#34d399" },
    IMPROVEMENT: { bg: "rgba(192,132,252,0.12)", color: "#c084fc" },
    OTHER:       { bg: "rgba(251,191,36,0.12)",  color: "#fbbf24" },
};

const priorityBorderColor = {
    LOW:    "rgba(113,113,122,0.4)",
    MEDIUM: "rgba(245,158,11,0.5)",
    HIGH:   "rgba(239,68,68,0.5)",
};

const ProjectCalendar = ({ tasks }) => {
    const [selectedDate, setSelectedDate] = useState(new Date());
    const [currentMonth, setCurrentMonth] = useState(new Date());

    const today = new Date();
    const getTasksForDate = (date) => tasks.filter(t => isSameDay(t.due_date, date));

    const upcomingTasks = tasks
        .filter(t => t.due_date && !isBefore(t.due_date, today) && t.status !== "done")
        .sort((a, b) => new Date(a.due_date) - new Date(b.due_date))
        .slice(0, 5);

    const overdueTasks = tasks.filter(
        t => t.due_date && isBefore(t.due_date, today) && t.status !== "done"
    );

    const daysInMonth = eachDayOfInterval({
        start: startOfMonth(currentMonth),
        end: endOfMonth(currentMonth),
    });

    const handleMonthChange = (dir) =>
        setCurrentMonth(prev => dir === "next" ? addMonths(prev, 1) : subMonths(prev, 1));

    const selectedDayTasks = getTasksForDate(selectedDate);

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 18rem", gap: "1.25rem", alignItems: "start" }} className="cal-grid">
            {/* Calendar */}
            <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                <div style={{
                    background: "var(--card)", backdropFilter: "blur(8px)",
                    border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                    padding: "1.25rem"
                }}>
                    {/* Month nav */}
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.25rem" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                            <Calendar size={16} strokeWidth={1.5} style={{ color: "var(--accent)" }} />
                            <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "0.9rem", color: "var(--fg)" }}>
                                Task Calendar
                            </h2>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                            <button onClick={() => handleMonthChange("prev")} className="btn btn-ghost btn-icon">
                                <ChevronLeft size={15} strokeWidth={1.5} />
                            </button>
                            <span style={{ fontSize: "0.85rem", fontWeight: 500, color: "var(--fg)", minWidth: "8rem", textAlign: "center", fontFamily: "'Space Grotesk', sans-serif" }}>
                                {format(currentMonth, "MMMM yyyy")}
                            </span>
                            <button onClick={() => handleMonthChange("next")} className="btn btn-ghost btn-icon">
                                <ChevronRight size={15} strokeWidth={1.5} />
                            </button>
                        </div>
                    </div>

                    {/* Day headers */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", marginBottom: "0.5rem" }}>
                        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map(d => (
                            <div key={d} style={{
                                textAlign: "center", fontSize: "0.65rem", fontWeight: 600,
                                color: "var(--fg-muted)", padding: "0.375rem 0",
                                fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.05em"
                            }}>
                                {d}
                            </div>
                        ))}
                    </div>

                    {/* Days grid */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: "0.25rem" }}>
                        {daysInMonth.map(day => {
                            const dayTasks = getTasksForDate(day);
                            const isSelected = isSameDay(day, selectedDate);
                            const isToday = isSameDay(day, today);
                            const hasOverdue = dayTasks.some(t => t.status !== "done" && isBefore(t.due_date, today));

                            return (
                                <button
                                    key={day.toISOString()}
                                    onClick={() => setSelectedDate(day)}
                                    style={{
                                        aspectRatio: "1",
                                        borderRadius: "var(--radius-md)",
                                        display: "flex", flexDirection: "column",
                                        alignItems: "center", justifyContent: "center",
                                        gap: "0.125rem", border: "none", cursor: "pointer",
                                        fontSize: "0.8rem", fontWeight: isToday ? 700 : 400,
                                        transition: "all 200ms ease-out",
                                        background: isSelected
                                            ? "var(--accent)"
                                            : isToday
                                                ? "rgba(245,158,11,0.12)"
                                                : "transparent",
                                        color: isSelected ? "var(--accent-fg)" : isToday ? "var(--accent)" : "var(--fg)",
                                        outline: hasOverdue && !isSelected ? "1px solid rgba(239,68,68,0.4)" : "none",
                                    }}
                                    onMouseEnter={e => {
                                        if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.06)"
                                    }}
                                    onMouseLeave={e => {
                                        if (!isSelected) e.currentTarget.style.background = isToday ? "rgba(245,158,11,0.12)" : "transparent"
                                    }}
                                >
                                    <span>{format(day, "d")}</span>
                                    {dayTasks.length > 0 && (
                                        <div style={{
                                            width: 4, height: 4, borderRadius: "50%",
                                            background: isSelected ? "var(--accent-fg)" : "var(--accent)"
                                        }} />
                                    )}
                                </button>
                            );
                        })}
                    </div>
                </div>

                {/* Tasks for selected day */}
                {selectedDayTasks.length > 0 && (
                    <div style={{
                        background: "var(--card)", backdropFilter: "blur(8px)",
                        border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                        overflow: "hidden"
                    }}>
                        <div style={{ padding: "0.875rem 1.25rem", borderBottom: "1px solid var(--border)" }}>
                            <h3 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "0.875rem", color: "var(--fg)" }}>
                                {format(selectedDate, "MMM d, yyyy")}
                                <span style={{ fontWeight: 400, color: "var(--fg-muted)", marginLeft: "0.5rem", fontSize: "0.8rem" }}>
                                    · {selectedDayTasks.length} task{selectedDayTasks.length !== 1 ? "s" : ""}
                                </span>
                            </h3>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0", padding: "0.75rem" }}>
                            {selectedDayTasks.map(task => {
                                const typeStyle = typeColors[task.type] || typeColors.OTHER;
                                const borderColor = priorityBorderColor[task.priority] || "var(--border)";
                                return (
                                    <div key={task.id} style={{
                                        padding: "0.75rem 1rem",
                                        borderRadius: "var(--radius-md)",
                                        background: "var(--bg-elevated)",
                                        border: "1px solid var(--border)",
                                        borderLeft: `3px solid ${borderColor}`,
                                        marginBottom: "0.5rem",
                                        transition: "background 200ms"
                                    }}
                                        onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
                                        onMouseLeave={e => e.currentTarget.style.background = "var(--bg-elevated)"}
                                    >
                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.375rem" }}>
                                            <h4 style={{ fontSize: "0.85rem", fontWeight: 500, color: "var(--fg)" }}>{task.title}</h4>
                                            <span style={{
                                                fontSize: "0.65rem", fontWeight: 600,
                                                background: typeStyle.bg, color: typeStyle.color,
                                                padding: "0.15rem 0.5rem", borderRadius: "var(--radius-full)",
                                                fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.04em"
                                            }}>
                                                {task.type}
                                            </span>
                                        </div>
                                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                                            <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                                {task.priority?.toLowerCase()} priority
                                            </span>
                                            {task.assignee && (
                                                <span style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.7rem", color: "var(--fg-muted)" }}>
                                                    <User size={11} strokeWidth={1.5} /> {task.assignee.name}
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}
            </div>

            {/* Sidebar */}
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                {/* Upcoming */}
                <div style={{
                    background: "var(--card)", backdropFilter: "blur(8px)",
                    border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                    overflow: "hidden"
                }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.875rem 1rem", borderBottom: "1px solid var(--border)" }}>
                        <Clock size={14} strokeWidth={1.5} style={{ color: "var(--accent)" }} />
                        <h3 style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--fg)" }}>Upcoming</h3>
                    </div>
                    <div style={{ padding: "0.75rem" }}>
                        {upcomingTasks.length === 0 ? (
                            <p style={{ fontSize: "0.8rem", color: "var(--fg-muted)", textAlign: "center", padding: "0.75rem 0" }}>No upcoming tasks</p>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
                                {upcomingTasks.map(task => {
                                    const typeStyle = typeColors[task.type] || typeColors.OTHER;
                                    return (
                                        <div key={task.id} style={{
                                            padding: "0.625rem 0.75rem",
                                            borderRadius: "var(--radius-md)",
                                            background: "var(--bg-elevated)",
                                            border: "1px solid var(--border)",
                                            transition: "background 200ms"
                                        }}
                                            onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
                                            onMouseLeave={e => e.currentTarget.style.background = "var(--bg-elevated)"}
                                        >
                                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.5rem" }}>
                                                <span style={{ fontSize: "0.8rem", color: "var(--fg)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                                    {task.title}
                                                </span>
                                                <span style={{
                                                    fontSize: "0.6rem", fontWeight: 600,
                                                    background: typeStyle.bg, color: typeStyle.color,
                                                    padding: "0.1rem 0.4rem", borderRadius: "var(--radius-full)",
                                                    fontFamily: "'JetBrains Mono', monospace", flexShrink: 0
                                                }}>
                                                    {task.type}
                                                </span>
                                            </div>
                                            <p style={{ fontSize: "0.7rem", color: "var(--fg-muted)", marginTop: "0.2rem", fontFamily: "'JetBrains Mono', monospace" }}>
                                                {format(task.due_date, "MMM d")}
                                            </p>
                                        </div>
                                    );
                                })}
                            </div>
                        )}
                    </div>
                </div>

                {/* Overdue */}
                {overdueTasks.length > 0 && (
                    <div style={{
                        background: "rgba(239,68,68,0.05)",
                        border: "1px solid rgba(239,68,68,0.2)",
                        borderLeft: "3px solid rgba(239,68,68,0.6)",
                        borderRadius: "var(--radius-lg)",
                        overflow: "hidden"
                    }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.875rem 1rem", borderBottom: "1px solid rgba(239,68,68,0.15)" }}>
                            <AlertTriangle size={14} strokeWidth={1.5} style={{ color: "#f87171" }} />
                            <h3 style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f87171" }}>
                                Overdue · {overdueTasks.length}
                            </h3>
                        </div>
                        <div style={{ padding: "0.75rem", display: "flex", flexDirection: "column", gap: "0.375rem" }}>
                            {overdueTasks.slice(0, 5).map(task => (
                                <div key={task.id} style={{
                                    padding: "0.625rem 0.75rem",
                                    borderRadius: "var(--radius-md)",
                                    background: "rgba(239,68,68,0.06)",
                                    border: "1px solid rgba(239,68,68,0.15)",
                                    transition: "background 200ms"
                                }}
                                    onMouseEnter={e => e.currentTarget.style.background = "rgba(239,68,68,0.1)"}
                                    onMouseLeave={e => e.currentTarget.style.background = "rgba(239,68,68,0.06)"}
                                >
                                    <div style={{ display: "flex", justifyContent: "space-between", gap: "0.5rem" }}>
                                        <span style={{ fontSize: "0.8rem", color: "var(--fg)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                            {task.title}
                                        </span>
                                        <span style={{
                                            fontSize: "0.6rem", fontWeight: 600,
                                            background: "rgba(239,68,68,0.15)", color: "#f87171",
                                            padding: "0.1rem 0.4rem", borderRadius: "var(--radius-full)",
                                            fontFamily: "'JetBrains Mono', monospace", flexShrink: 0
                                        }}>
                                            {task.type}
                                        </span>
                                    </div>
                                    <p style={{ fontSize: "0.7rem", color: "#f87171", marginTop: "0.2rem", fontFamily: "'JetBrains Mono', monospace" }}>
                                        Due {format(task.due_date, "MMM d")}
                                    </p>
                                </div>
                            ))}
                            {overdueTasks.length > 5 && (
                                <p style={{ fontSize: "0.7rem", color: "#f87171", textAlign: "center", padding: "0.25rem" }}>
                                    +{overdueTasks.length - 5} more
                                </p>
                            )}
                        </div>
                    </div>
                )}
            </div>

            <style>{`
                @media (max-width: 900px) {
                    .cal-grid { grid-template-columns: 1fr !important; }
                }
            `}</style>
        </div>
    );
};

export default ProjectCalendar;