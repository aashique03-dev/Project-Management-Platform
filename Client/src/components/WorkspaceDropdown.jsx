import { useState, useRef, useEffect } from "react";
import { ChevronDown, Check, Plus, Loader2 } from "lucide-react";
import { useDispatch, useSelector } from "react-redux";
import { setCurrentWorkspace, fetchWorkspaces } from "../features/workspaceSlice";
import { useNavigate } from "react-router-dom";

const WorkspaceDropdown = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { list: workspaces = [], current: currentWorkspace, loading } = useSelector(state => state.workspace);

    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef(null);

    useEffect(() => { dispatch(fetchWorkspaces()); }, [dispatch]);

    useEffect(() => {
        const handler = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) setIsOpen(false);
        };
        document.addEventListener("mousedown", handler);
        return () => document.removeEventListener("mousedown", handler);
    }, []);

    const onSelect = (id) => {
        dispatch(setCurrentWorkspace(id));
        setIsOpen(false);
        navigate("/");
    };

    if (loading) return (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "1rem" }}>
            <Loader2 size={18} strokeWidth={1.5} style={{ color: "var(--accent)", animation: "spin 0.8s linear infinite" }} />
        </div>
    );

    if (!workspaces.length) return (
        <div style={{ padding: "1rem", fontSize: "0.8rem", color: "var(--fg-muted)", textAlign: "center" }}>
            No workspaces available
        </div>
    );

    return (
        <div style={{ position: "relative", padding: "0.625rem" }} ref={dropdownRef}>
            <button
                onClick={() => setIsOpen(p => !p)}
                style={{
                    width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "0.625rem 0.75rem",
                    borderRadius: "var(--radius-md)",
                    background: "transparent",
                    border: "1px solid var(--border)",
                    cursor: "pointer", transition: "all 200ms ease-out"
                }}
                onMouseEnter={e => {
                    e.currentTarget.style.background = "rgba(255,255,255,0.04)"
                    e.currentTarget.style.borderColor = "var(--border-hover)"
                }}
                onMouseLeave={e => {
                    e.currentTarget.style.background = "transparent"
                    e.currentTarget.style.borderColor = "var(--border)"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "0.625rem", minWidth: 0, flex: 1 }}>
                    {currentWorkspace?.image_url && (
                        <img src={currentWorkspace.image_url} alt={currentWorkspace.name}
                            style={{ width: 24, height: 24, borderRadius: "var(--radius-sm)", flexShrink: 0 }} />
                    )}
                    <div style={{ minWidth: 0, flex: 1, textAlign: "left" }}>
                        <p style={{
                            fontSize: "0.8rem", fontWeight: 600,
                            color: "var(--fg)", overflow: "hidden",
                            textOverflow: "ellipsis", whiteSpace: "nowrap",
                            fontFamily: "'Space Grotesk', sans-serif"
                        }}>
                            {currentWorkspace?.name || "Select Workspace"}
                        </p>
                        <p style={{ fontSize: "0.65rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                            {workspaces.length} workspace{workspaces.length !== 1 ? "s" : ""}
                        </p>
                    </div>
                </div>
                <ChevronDown size={13} strokeWidth={1.5} style={{
                    color: "var(--fg-muted)", flexShrink: 0,
                    transform: isOpen ? "rotate(180deg)" : "rotate(0)",
                    transition: "transform 200ms"
                }} />
            </button>

            {isOpen && (
                <div style={{
                    position: "absolute", top: "calc(100% - 0.25rem)", left: "0.625rem", right: "0.625rem",
                    background: "var(--bg-alt)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-lg)",
                    boxShadow: "var(--shadow-lg)",
                    zIndex: 50, overflow: "hidden",
                    animation: "slideUp 150ms ease-out"
                }}>
                    <div style={{ padding: "0.375rem" }}>
                        <p style={{
                            fontSize: "0.65rem", fontWeight: 600,
                            color: "var(--fg-muted)", textTransform: "uppercase",
                            letterSpacing: "0.08em", padding: "0.375rem 0.625rem 0.25rem",
                            fontFamily: "'JetBrains Mono', monospace"
                        }}>
                            Workspaces
                        </p>
                        {workspaces.map(ws => {
                            const wsId = ws._id || ws.id;
                            const isActive = currentWorkspace?.id === ws.id || currentWorkspace?._id === ws._id;
                            return (
                                <div
                                    key={wsId}
                                    onClick={() => onSelect(wsId)}
                                    style={{
                                        display: "flex", alignItems: "center", gap: "0.625rem",
                                        padding: "0.5rem 0.625rem",
                                        borderRadius: "var(--radius-md)",
                                        cursor: "pointer", transition: "background 150ms",
                                        background: isActive ? "var(--accent-muted)" : "transparent"
                                    }}
                                    onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = "rgba(255,255,255,0.04)" }}
                                    onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = "transparent" }}
                                >
                                    {ws.image_url && (
                                        <img src={ws.image_url} alt={ws.name}
                                            style={{ width: 22, height: 22, borderRadius: "var(--radius-sm)", flexShrink: 0 }} />
                                    )}
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <p style={{
                                            fontSize: "0.8rem", fontWeight: 500,
                                            color: isActive ? "var(--accent)" : "var(--fg)",
                                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                                        }}>
                                            {ws.name}
                                        </p>
                                        <p style={{ fontSize: "0.65rem", color: "var(--fg-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                                            {ws.membersCount || 0} members
                                        </p>
                                    </div>
                                    {isActive && <Check size={13} strokeWidth={2} style={{ color: "var(--accent)", flexShrink: 0 }} />}
                                </div>
                            );
                        })}
                    </div>

                    <div style={{ borderTop: "1px solid var(--border)", padding: "0.375rem" }}>
                        <button style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            width: "100%", padding: "0.5rem 0.625rem",
                            borderRadius: "var(--radius-md)",
                            background: "transparent", border: "none", cursor: "pointer",
                            fontSize: "0.8rem", color: "var(--accent)", fontWeight: 500,
                            transition: "background 150ms"
                        }}
                            onMouseEnter={e => e.currentTarget.style.background = "var(--accent-muted)"}
                            onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                        >
                            <Plus size={14} strokeWidth={1.5} /> Create Workspace
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default WorkspaceDropdown;