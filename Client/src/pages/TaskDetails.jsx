import { format } from "date-fns";
import toast from "react-hot-toast";
import { useSelector } from "react-redux";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Calendar, MessageCircle, Pen, Send, Loader2 } from "lucide-react";
import { assets } from "../assets/assets";

const statusBadge = {
    todo:        { label: "To Do",       cls: "badge-todo"        },
    in_progress: { label: "In Progress", cls: "badge-in-progress" },
    done:        { label: "Done",        cls: "badge-done"        },
}

const priorityBadge = {
    LOW:    "badge-low",
    MEDIUM: "badge-medium",
    HIGH:   "badge-high",
}

const TaskDetails = () => {
    const [searchParams] = useSearchParams();
    const projectId = searchParams.get("projectId");
    const taskId    = searchParams.get("taskId");

    const user = { id: 'user_1' };
    const [task, setTask]       = useState(null);
    const [project, setProject] = useState(null);
    const [comments, setComments]   = useState([]);
    const [newComment, setNewComment] = useState("");
    const [loading, setLoading]     = useState(true);
    const [posting, setPosting]     = useState(false);

    const { currentWorkspace } = useSelector(state => state.workspace);

    const fetchTaskDetails = () => {
        setLoading(true);
        if (!projectId || !taskId) return;
        const proj = currentWorkspace?.projects.find(p => p.id === projectId || p._id === projectId);
        if (!proj) return;
        const tsk = proj.tasks.find(t => t.id === taskId || t._id === taskId);
        if (!tsk) return;
        setTask(tsk);
        setProject(proj);
        setLoading(false);
    };

    const handleAddComment = async () => {
        if (!newComment.trim()) return;
        setPosting(true);
        try {
            toast.loading("Adding comment...");
            await new Promise(r => setTimeout(r, 1500));
            const dummy = {
                id: Date.now(),
                user: { id: 1, name: "User", image: assets.profile_img_a },
                content: newComment,
                createdAt: new Date()
            };
            setComments(prev => [...prev, dummy]);
            setNewComment("");
            toast.dismiss();
            toast.success("Comment added.");
        } catch (err) {
            toast.dismiss();
            toast.error(err?.message || "Failed to add comment");
        } finally {
            setPosting(false);
        }
    };

    useEffect(() => { fetchTaskDetails(); }, [taskId]);

    if (loading) return (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "6rem 2rem", gap: "0.625rem", color: "var(--fg-muted)" }}>
            <Loader2 size={18} strokeWidth={1.5} style={{ animation: "spin 0.8s linear infinite", color: "var(--accent)" }} />
            <span style={{ fontSize: "0.875rem" }}>Loading task details...</span>
        </div>
    );

    if (!task) return (
        <div style={{ textAlign: "center", padding: "6rem 2rem" }}>
            <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: "1.5rem", fontWeight: 700, color: "var(--fg-muted)" }}>
                Task not found
            </p>
        </div>
    );

    const status   = statusBadge[task.status];
    const priority = priorityBadge[task.priority];

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 22rem", gap: "1.25rem", alignItems: "start" }} className="task-detail-grid">

            {/* Left: Comments */}
            <div style={{
                background: "var(--card)", backdropFilter: "blur(8px)",
                border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                display: "flex", flexDirection: "column",
                height: "calc(100vh - 8rem)", overflow: "hidden"
            }}>
                {/* Header */}
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "1rem 1.25rem", borderBottom: "1px solid var(--border)" }}>
                    <MessageCircle size={16} strokeWidth={1.5} style={{ color: "var(--accent)" }} />
                    <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "0.9rem", color: "var(--fg)" }}>
                        Discussion
                    </h2>
                    <span style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: "0.65rem", fontWeight: 600,
                        background: "var(--bg-elevated)", color: "var(--fg-muted)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius-full)", padding: "0 0.375rem",
                        lineHeight: "1.4rem", marginLeft: "0.25rem"
                    }}>
                        {comments.length}
                    </span>
                </div>

                {/* Messages */}
                <div style={{ flex: 1, overflowY: "auto", padding: "1rem 1.25rem" }} className="no-scrollbar">
                    {comments.length === 0 ? (
                        <div style={{ textAlign: "center", padding: "3rem 1rem" }}>
                            <MessageCircle size={32} strokeWidth={1} style={{ color: "var(--fg-muted)", margin: "0 auto 0.75rem" }} />
                            <p style={{ fontSize: "0.875rem", color: "var(--fg-muted)" }}>No comments yet. Be the first!</p>
                        </div>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                            {comments.map(comment => {
                                const isOwn = comment.user.id === user?.id;
                                return (
                                    <div key={comment.id} style={{
                                        maxWidth: "80%",
                                        marginLeft: isOwn ? "auto" : "0",
                                        background: isOwn ? "var(--accent-muted)" : "var(--bg-elevated)",
                                        border: `1px solid ${isOwn ? "var(--border-accent)" : "var(--border)"}`,
                                        borderRadius: "var(--radius-lg)",
                                        padding: "0.625rem 0.875rem"
                                    }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem" }}>
                                            <img src={comment.user.image} alt="avatar"
                                                style={{ width: 18, height: 18, borderRadius: "50%", flexShrink: 0 }} />
                                            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: isOwn ? "var(--accent)" : "var(--fg)" }}>
                                                {comment.user.name}
                                            </span>
                                            <span style={{ fontSize: "0.65rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace", marginLeft: "auto" }}>
                                                {format(new Date(comment.createdAt), "MMM d, HH:mm")}
                                            </span>
                                        </div>
                                        <p style={{ fontSize: "0.85rem", color: "var(--fg)", lineHeight: 1.55 }}>
                                            {comment.content}
                                        </p>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Input */}
                <div style={{ padding: "0.875rem 1.25rem", borderTop: "1px solid var(--border)", display: "flex", gap: "0.625rem", alignItems: "flex-end" }}>
                    <textarea
                        value={newComment}
                        onChange={e => setNewComment(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleAddComment(); } }}
                        placeholder="Write a comment... (Enter to send)"
                        className="input"
                        style={{ flex: 1, height: "4.5rem", resize: "none", lineHeight: 1.5 }}
                    />
                    <button
                        onClick={handleAddComment}
                        disabled={posting || !newComment.trim()}
                        className="btn btn-primary btn-icon"
                        style={{ height: "2.75rem", width: "2.75rem", flexShrink: 0 }}
                        aria-label="Send comment"
                    >
                        {posting
                            ? <Loader2 size={15} strokeWidth={1.5} style={{ animation: "spin 0.8s linear infinite" }} />
                            : <Send size={15} strokeWidth={1.5} />
                        }
                    </button>
                </div>
            </div>

            {/* Right: Task + Project info */}
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                {/* Task info */}
                <div style={{
                    background: "var(--card)", backdropFilter: "blur(8px)",
                    border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                    padding: "1.25rem"
                }}>
                    <h1 style={{
                        fontFamily: "'Space Grotesk', sans-serif",
                        fontWeight: 700, fontSize: "1.05rem",
                        letterSpacing: "-0.02em", color: "var(--fg)",
                        marginBottom: "0.75rem", lineHeight: 1.3
                    }}>
                        {task.title}
                    </h1>

                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.375rem", marginBottom: "1rem" }}>
                        {status   && <span className={`badge ${status.cls}`}>{status.label}</span>}
                        {task.type && <span style={{
                            fontSize: "0.65rem", fontWeight: 600,
                            background: "rgba(96,165,250,0.12)", color: "#60a5fa",
                            border: "1px solid rgba(96,165,250,0.2)",
                            borderRadius: "var(--radius-full)", padding: "0.15rem 0.5rem",
                            fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.04em"
                        }}>{task.type}</span>}
                        {priority && <span className={`badge ${priority}`}>{task.priority}</span>}
                    </div>

                    {task.description && (
                        <p style={{ fontSize: "0.85rem", color: "var(--fg-muted)", lineHeight: 1.65, marginBottom: "1rem" }}>
                            {task.description}
                        </p>
                    )}

                    <div style={{ height: "1px", background: "var(--border)", margin: "0.875rem 0" }} />

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                        <div>
                            <p style={{ fontSize: "0.65rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace", marginBottom: "0.375rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                                Assignee
                            </p>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                {task.assignee?.image
                                    ? <img src={task.assignee.image} style={{ width: 20, height: 20, borderRadius: "50%" }} alt="avatar" />
                                    : <div style={{ width: 20, height: 20, borderRadius: "50%", background: "var(--bg-elevated)", border: "1px solid var(--border)" }} />
                                }
                                <span style={{ fontSize: "0.8rem", color: "var(--fg)" }}>
                                    {task.assignee?.name || "Unassigned"}
                                </span>
                            </div>
                        </div>
                        <div>
                            <p style={{ fontSize: "0.65rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace", marginBottom: "0.375rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                                Due Date
                            </p>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                                <Calendar size={13} strokeWidth={1.5} style={{ color: "var(--fg-muted)" }} />
                                <span style={{ fontSize: "0.8rem", color: "var(--fg)" }}>
                                    {task.due_date ? format(new Date(task.due_date), "MMM d, yyyy") : "—"}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Project info */}
                {project && (
                    <div style={{
                        background: "var(--card)", backdropFilter: "blur(8px)",
                        border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
                        padding: "1.25rem"
                    }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.875rem" }}>
                            <Pen size={14} strokeWidth={1.5} style={{ color: "var(--accent)" }} />
                            <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: "0.875rem", color: "var(--fg)" }}>
                                Project
                            </h2>
                        </div>
                        <p style={{ fontWeight: 600, fontSize: "0.9rem", color: "var(--fg)", marginBottom: "0.625rem" }}>
                            {project.name}
                        </p>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginBottom: "0.875rem" }}>
                            <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                Status: <span style={{ color: "var(--fg)" }}>{project.status}</span>
                            </span>
                            <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                · Priority: <span style={{ color: "var(--fg)" }}>{project.priority}</span>
                            </span>
                        </div>
                        <div>
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.375rem" }}>
                                <span style={{ fontSize: "0.7rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>Progress</span>
                                <span style={{ fontSize: "0.7rem", color: "var(--accent)", fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>{project.progress}%</span>
                            </div>
                            <div className="progress-track">
                                <div className="progress-fill" style={{ width: `${project.progress || 0}%` }} />
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <style>{`
                @media (max-width: 900px) {
                    .task-detail-grid {
                        grid-template-columns: 1fr !important;
                    }
                }
            `}</style>
        </div>
    );
};

export default TaskDetails;