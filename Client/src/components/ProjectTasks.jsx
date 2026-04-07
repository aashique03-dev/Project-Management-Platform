import { format } from "date-fns";
import toast from "react-hot-toast";
import { useDispatch } from "react-redux";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { deleteTask, updateTask } from "../features/workspaceSlice";
import { Bug, CalendarIcon, GitCommit, MessageSquare, Square, Trash, X, Zap } from "lucide-react";

const typeIcons = {
    BUG:         { icon: Bug,           color: "#f87171" },
    FEATURE:     { icon: Zap,           color: "#60a5fa" },
    TASK:        { icon: Square,        color: "#34d399" },
    IMPROVEMENT: { icon: GitCommit,     color: "#c084fc" },
    OTHER:       { icon: MessageSquare, color: "#fbbf24" },
};

const priorityStyles = {
    LOW:    { background: "rgba(113,113,122,0.15)", color: "#a1a1aa" },
    MEDIUM: { background: "rgba(245,158,11,0.12)",  color: "#fbbf24" },
    HIGH:   { background: "rgba(239,68,68,0.12)",   color: "#f87171" },
};

const statusStyles = {
    todo:        { label: "To Do",       background: "rgba(113,113,122,0.15)", color: "#a1a1aa" },
    in_progress: { label: "In Progress", background: "rgba(245,158,11,0.12)",  color: "#fbbf24" },
    done:        { label: "Done",        background: "rgba(52,211,153,0.12)",  color: "#34d399" },
};

const formatDate = (date) => {
    if (!date) return "—";
    const d = new Date(date);
    if (isNaN(d.getTime())) return "—";
    return format(d, "dd MMM");
};

const ProjectTasks = ({ tasks }) => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [selectedTasks, setSelectedTasks] = useState([]);
    const [filters, setFilters] = useState({ status: "", type: "", priority: "", assignee: "" });

    const assigneeList = useMemo(
        () => Array.from(new Set(tasks.map(t => t.assignee?.name).filter(Boolean))),
        [tasks]
    );

    const filteredTasks = useMemo(() => tasks.filter(task => {
        const { status, type, priority, assignee } = filters;
        return (
            (!status   || task.status         === status)   &&
            (!type     || task.type           === type)     &&
            (!priority || task.priority       === priority) &&
            (!assignee || task.assignee?.name === assignee)
        );
    }), [filters, tasks]);

    const handleFilterChange = (e) => {
        const { name, value } = e.target;
        setFilters(prev => ({ ...prev, [name]: value }));
    };

    const handleStatusChange = async (taskId, newStatus) => {
        try {
            toast.loading("Updating status...");
            await new Promise(r => setTimeout(r, 1000));
            const updatedTask = structuredClone(tasks.find(t => t._id === taskId || t.id === taskId));
            updatedTask.status = newStatus;
            dispatch(updateTask(updatedTask));
            toast.dismiss();
            toast.success("Status updated");
        } catch (error) {
            toast.dismiss();
            toast.error(error?.response?.data?.message || error.message);
        }
    };

    const handleDelete = async () => {
        if (!window.confirm("Delete selected tasks?")) return;
        try {
            toast.loading("Deleting...");
            for (const taskId of selectedTasks) {
                const taskObj = tasks.find(t => t.id === taskId || t._id === taskId);
                if (taskObj) await dispatch(deleteTask({ taskId, projectId: taskObj.projectId })).unwrap();
            }
            setSelectedTasks([]);
            toast.dismiss();
            toast.success("Tasks deleted");
        } catch (error) {
            toast.dismiss();
            toast.error(error?.message || "Failed to delete");
        }
    };

    const filterSelectStyle = {
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        color: "var(--fg)",
        fontSize: "0.8rem",
        padding: "0.4rem 0.75rem",
        outline: "none",
        cursor: "pointer",
        fontFamily: "'Inter', sans-serif",
        colorScheme: "dark",
    };

    const getStatusSelectStyle = (status) => {
        const s = statusStyles[status] || statusStyles.todo;
        return {
            background: s.background,
            color: s.color,
            border: `1px solid ${s.color}30`,
            borderRadius: "var(--radius-md)",
            fontSize: "0.75rem",
            fontWeight: 500,
            padding: "0.3rem 0.6rem",
            outline: "none",
            cursor: "pointer",
            fontFamily: "'Inter', sans-serif",
            colorScheme: "dark",
            minWidth: "8rem",
        };
    };

    return (
        <div>
            {/* Filters */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginBottom: "1.25rem" }}>
                {["status", "type", "priority", "assignee"].map(name => {
                    const options = {
                        status:   [{ label: "All Statuses", value: "" }, { label: "To Do", value: "todo" }, { label: "In Progress", value: "in_progress" }, { label: "Done", value: "done" }],
                        type:     [{ label: "All Types", value: "" }, { label: "Task", value: "TASK" }, { label: "Bug", value: "BUG" }, { label: "Feature", value: "FEATURE" }, { label: "Improvement", value: "IMPROVEMENT" }, { label: "Other", value: "OTHER" }],
                        priority: [{ label: "All Priorities", value: "" }, { label: "Low", value: "LOW" }, { label: "Medium", value: "MEDIUM" }, { label: "High", value: "HIGH" }],
                        assignee: [{ label: "All Assignees", value: "" }, ...assigneeList.map(n => ({ label: n, value: n }))],
                    };
                    return (
                        <select key={name} name={name} onChange={handleFilterChange} style={filterSelectStyle}>
                            {options[name].map((opt, i) => (
                                <option key={i} value={opt.value}>{opt.label}</option>
                            ))}
                        </select>
                    );
                })}

                {Object.values(filters).some(Boolean) && (
                    <button
                        onClick={() => setFilters({ status: "", type: "", priority: "", assignee: "" })}
                        style={{ ...filterSelectStyle, display: "flex", alignItems: "center", gap: "0.375rem", border: "1px solid var(--border)" }}
                    >
                        <X size={12} /> Reset
                    </button>
                )}

                {selectedTasks.length > 0 && (
                    <button
                        onClick={handleDelete}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.375rem",
                            background: "rgba(239,68,68,0.12)", color: "#f87171",
                            border: "1px solid rgba(239,68,68,0.2)",
                            borderRadius: "var(--radius-md)", fontSize: "0.8rem",
                            padding: "0.4rem 0.75rem", cursor: "pointer",
                            fontFamily: "'Inter', sans-serif"
                        }}
                    >
                        <Trash size={12} /> Delete ({selectedTasks.length})
                    </button>
                )}
            </div>

            {/* Desktop Table */}
            <div className="table-wrapper" id="tasks-table">
                <table>
                    <thead>
                        <tr>
                            <th style={{ width: "2.5rem" }}>
                                <input
                                    type="checkbox"
                                    onChange={() => selectedTasks.length === tasks.length
                                        ? setSelectedTasks([])
                                        : setSelectedTasks(tasks.map(t => t._id || t.id))
                                    }
                                    checked={selectedTasks.length === tasks.length && tasks.length > 0}
                                />
                            </th>
                            <th>Title</th>
                            <th>Type</th>
                            <th>Priority</th>
                            <th>Status</th>
                            <th>Assignee</th>
                            <th>Due</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredTasks.length > 0 ? filteredTasks.map(task => {
                            const taskId = task._id || task.id;
                            const typeInfo = typeIcons[task.type] || typeIcons.OTHER;
                            const TypeIcon = typeInfo.icon;
                            const pStyle = priorityStyles[task.priority] || {};

                            return (
                                <tr
                                    key={taskId}
                                    onClick={() => navigate(`/taskDetails?projectId=${task.project || task.projectId}&taskId=${taskId}`)}
                                    style={{ cursor: "pointer" }}
                                >
                                    <td onClick={e => e.stopPropagation()}>
                                        <input
                                            type="checkbox"
                                            checked={selectedTasks.includes(taskId)}
                                            onChange={() => selectedTasks.includes(taskId)
                                                ? setSelectedTasks(selectedTasks.filter(i => i !== taskId))
                                                : setSelectedTasks(prev => [...prev, taskId])
                                            }
                                        />
                                    </td>
                                    <td style={{ fontWeight: 500, color: "var(--fg)" }}>{task.title}</td>
                                    <td>
                                        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                                            <TypeIcon size={14} strokeWidth={1.5} style={{ color: typeInfo.color }} />
                                            <span style={{ fontSize: "0.72rem", color: typeInfo.color, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                                                {task.type}
                                            </span>
                                        </div>
                                    </td>
                                    <td>
                                        <span style={{
                                            fontSize: "0.68rem", fontWeight: 600,
                                            padding: "0.2rem 0.55rem", borderRadius: "var(--radius-full)",
                                            background: pStyle.background, color: pStyle.color,
                                            fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.04em"
                                        }}>
                                            {task.priority}
                                        </span>
                                    </td>
                                    <td onClick={e => e.stopPropagation()}>
                                        {/* ✅ Dark-themed status select — no browser white popup */}
                                        <select
                                            value={task.status}
                                            onChange={e => handleStatusChange(taskId, e.target.value)}
                                            style={getStatusSelectStyle(task.status)}
                                        >
                                            <option value="todo">To Do</option>
                                            <option value="in_progress">In Progress</option>
                                            <option value="done">Done</option>
                                        </select>
                                    </td>
                                    <td>
                                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                            {task.assignee?.image
                                                ? <img src={task.assignee.image} style={{ width: 20, height: 20, borderRadius: "50%" }} alt="" />
                                                : <div style={{ width: 20, height: 20, borderRadius: "50%", background: "var(--bg-elevated)", border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.6rem", color: "var(--fg-muted)" }}>?</div>
                                            }
                                            <span style={{ fontSize: "0.8rem", color: "var(--fg-muted)" }}>
                                                {task.assignee?.name || "—"}
                                            </span>
                                        </div>
                                    </td>
                                    <td>
                                        <div style={{ display: "flex", alignItems: "center", gap: "0.375rem", color: "var(--fg-muted)" }}>
                                            <CalendarIcon size={13} strokeWidth={1.5} />
                                            <span style={{ fontSize: "0.75rem", fontFamily: "'JetBrains Mono', monospace" }}>
                                                {formatDate(task.dueDate || task.due_date)}
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            );
                        }) : (
                            <tr>
                                <td colSpan="7" style={{ textAlign: "center", color: "var(--fg-muted)", padding: "3rem", fontSize: "0.875rem" }}>
                                    No tasks match the selected filters.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Mobile Cards */}
            <div id="tasks-cards" style={{ display: "none", flexDirection: "column", gap: "0.75rem" }}>
                {filteredTasks.length > 0 ? filteredTasks.map(task => {
                    const taskId = task._id || task.id;
                    const typeInfo = typeIcons[task.type] || typeIcons.OTHER;
                    const TypeIcon = typeInfo.icon;
                    const pStyle = priorityStyles[task.priority] || {};

                    return (
                        <div
                            key={taskId}
                            onClick={() => navigate(`/taskDetails?projectId=${task.project || task.projectId}&taskId=${taskId}`)}
                            style={{
                                background: "var(--card)", border: "1px solid var(--border)",
                                borderRadius: "var(--radius-lg)", padding: "1rem",
                                display: "flex", flexDirection: "column", gap: "0.625rem",
                                cursor: "pointer", transition: "background 200ms"
                            }}
                            onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                            onMouseLeave={e => e.currentTarget.style.background = "var(--card)"}
                        >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                                <h3 style={{ fontSize: "0.875rem", fontWeight: 600, color: "var(--fg)" }}>{task.title}</h3>
                                <input
                                    type="checkbox"
                                    checked={selectedTasks.includes(taskId)}
                                    onClick={e => e.stopPropagation()}
                                    onChange={() => selectedTasks.includes(taskId)
                                        ? setSelectedTasks(selectedTasks.filter(i => i !== taskId))
                                        : setSelectedTasks(prev => [...prev, taskId])
                                    }
                                />
                            </div>

                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                <TypeIcon size={13} strokeWidth={1.5} style={{ color: typeInfo.color }} />
                                <span style={{ fontSize: "0.72rem", color: typeInfo.color, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                                    {task.type}
                                </span>
                                <span style={{
                                    marginLeft: "auto",
                                    fontSize: "0.65rem", fontWeight: 600,
                                    padding: "0.15rem 0.5rem", borderRadius: "var(--radius-full)",
                                    background: pStyle.background, color: pStyle.color,
                                    fontFamily: "'JetBrains Mono', monospace"
                                }}>
                                    {task.priority}
                                </span>
                            </div>

                            <div onClick={e => e.stopPropagation()}>
                                <label style={{ fontSize: "0.65rem", color: "var(--fg-muted)", display: "block", marginBottom: "0.25rem", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                                    Status
                                </label>
                                <select
                                    value={task.status}
                                    onChange={e => handleStatusChange(taskId, e.target.value)}
                                    style={{ ...getStatusSelectStyle(task.status), width: "100%" }}
                                >
                                    <option value="todo">To Do</option>
                                    <option value="in_progress">In Progress</option>
                                    <option value="done">Done</option>
                                </select>
                            </div>

                            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                                    {task.assignee?.image
                                        ? <img src={task.assignee.image} style={{ width: 18, height: 18, borderRadius: "50%" }} alt="" />
                                        : <div style={{ width: 18, height: 18, borderRadius: "50%", background: "var(--bg-elevated)", border: "1px solid var(--border)" }} />
                                    }
                                    <span style={{ fontSize: "0.78rem", color: "var(--fg-muted)" }}>{task.assignee?.name || "Unassigned"}</span>
                                </div>
                                <div style={{ display: "flex", alignItems: "center", gap: "0.25rem", color: "var(--fg-muted)" }}>
                                    <CalendarIcon size={12} strokeWidth={1.5} />
                                    <span style={{ fontSize: "0.75rem", fontFamily: "'JetBrains Mono', monospace" }}>
                                        {formatDate(task.dueDate || task.due_date)}
                                    </span>
                                </div>
                            </div>
                        </div>
                    );
                }) : (
                    <p style={{ textAlign: "center", color: "var(--fg-muted)", padding: "2rem", fontSize: "0.875rem" }}>
                        No tasks match the selected filters.
                    </p>
                )}
            </div>

            <style>{`
                @media (max-width: 768px) {
                    #tasks-table { display: none !important; }
                    #tasks-cards { display: flex !important; }
                }
                /* Force dark background on all select option dropdowns */
                select option {
                    background-color: #1A1A24 !important;
                    color: #FAFAFA !important;
                }
            `}</style>
        </div>
    );
};

export default ProjectTasks;