import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
    CheckCircle, LayoutDashboard, Users, Calendar,
    BarChart2, Bell, ArrowRight, Zap, Shield, Star,
    Moon, Sun, Menu, X, ChevronRight, Target,
    Clock, TrendingUp, Layers, GitBranch
} from "lucide-react";

// ── Color System ────────────────────────────────────────────────────
const theme = {
    light: {
        bg: "#FFFFFF",
        bgSoft: "#F7F8FC",
        bgCard: "#FFFFFF",
        border: "#E8EAF0",
        borderSoft: "#F0F1F6",
        text: "#0D0F1A",
        textSec: "#4A5068",
        textMuted: "#9197AE",
        accent: "#4F46E5",
        accentHover: "#4338CA",
        accentSoft: "#EEF2FF",
        accentText: "#FFFFFF",
        success: "#059669",
        successSoft: "#ECFDF5",
        warning: "#D97706",
        warningSoft: "#FFFBEB",
        danger: "#DC2626",
        dangerSoft: "#FEF2F2",
        navBg: "rgba(255,255,255,0.85)",
        shadow: "0 1px 3px rgba(0,0,0,0.08), 0 8px 32px rgba(79,70,229,0.06)",
        shadowCard: "0 2px 12px rgba(0,0,0,0.06)",
    },
    dark: {
        bg: "#0A0C14",
        bgSoft: "#0F1220",
        bgCard: "#141827",
        border: "#1E2336",
        borderSoft: "#181C2C",
        text: "#EEF0F8",
        textSec: "#8B90A8",
        textMuted: "#4A5068",
        accent: "#6366F1",
        accentHover: "#818CF8",
        accentSoft: "#1A1D35",
        accentText: "#FFFFFF",
        success: "#34D399",
        successSoft: "#022C22",
        warning: "#FBBF24",
        warningSoft: "#1C1400",
        danger: "#F87171",
        dangerSoft: "#1C0505",
        navBg: "rgba(10,12,20,0.85)",
        shadow: "0 1px 3px rgba(0,0,0,0.3), 0 8px 32px rgba(99,102,241,0.08)",
        shadowCard: "0 2px 12px rgba(0,0,0,0.3)",
    }
};

const features = [
    { icon: LayoutDashboard, title: "Smart Dashboard", desc: "Real-time overview of all projects, deadlines, and team activity in one unified view." },
    { icon: Users, title: "Team Collaboration", desc: "Assign tasks, set roles, comment inline, and keep everyone aligned without the noise." },
    { icon: CheckCircle, title: "Task Management", desc: "Create, prioritize, and track tasks with custom statuses, tags, and due dates." },
    { icon: BarChart2, title: "Analytics & Reports", desc: "Visualize productivity trends, bottlenecks, and team performance with clear charts." },
    { icon: Calendar, title: "Timeline & Calendar", desc: "See your entire project roadmap in a Gantt-style view with drag-and-drop scheduling." },
    { icon: Bell, title: "Smart Notifications", desc: "Never miss a deadline. Get intelligent alerts for blockers, mentions, and updates." },
];

const workflow = [
    { step: "01", icon: Target, title: "Define your project", desc: "Set goals, milestones, and invite your team in minutes." },
    { step: "02", icon: Layers, title: "Break it into tasks", desc: "Create task lists, assign owners, and set priorities." },
    { step: "03", icon: GitBranch, title: "Track in real time", desc: "Monitor progress on a live board as work moves forward." },
    { step: "04", icon: TrendingUp, title: "Ship and improve", desc: "Analyse what worked, iterate fast, and deliver on time." },
];

const testimonials = [
    { name: "Sarah Chen", role: "Head of Product, Vercel", text: "This replaced Jira, Notion, and Slack threads for us. Our team ships 40% faster.", stars: 5, avatar: "SC" },
    { name: "Marcus Webb", role: "Engineering Lead, Stripe", text: "The cleanest project tool I've used. It stays out of the way and just works.", stars: 5, avatar: "MW" },
    { name: "Aisha Patel", role: "Founder, Luminary", text: "We replaced 3 tools with this one. Onboarding took 10 minutes. Team loved it immediately.", stars: 5, avatar: "AP" },
];

// ── Dashboard Preview ───────────────────────────────────────────────
const DashboardPreview = ({ t }) => (
    <div className="relative rounded-2xl overflow-hidden"
        style={{ backgroundColor: t.bgCard, border: `0.5px solid ${t.border}`, boxShadow: t.shadow }}>

        {/* Top bar */}
        <div className="flex items-center gap-2 px-4 py-3 border-b"
            style={{ borderColor: t.border, backgroundColor: t.bgSoft }}>
            <div className="flex gap-1.5">
                {['#FF5F57', '#FEBC2E', '#28C840'].map((c, i) => (
                    <div key={i} className="w-3 h-3 rounded-full" style={{ backgroundColor: c }} />
                ))}
            </div>
            <div className="flex-1 mx-4 h-5 rounded" style={{ backgroundColor: t.border }} />
        </div>

        {/* Stat cards — full-bleed grid with divider lines */}
        <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
            gap: '1px',
            backgroundColor: t.border,
        }}>
            {[
                { label: "Projects",   val: "12",  color: t.accent  },
                { label: "Tasks Done", val: "84%", color: t.success },
                { label: "Overdue",    val: "3",   color: t.danger  },
            ].map((s, i) => (
                <div key={i} style={{ backgroundColor: t.bgCard, padding: '14px 16px' }}>
                    <p style={{ fontSize: '12px', color: t.textMuted, marginBottom: '4px' }}>{s.label}</p>
                    <p style={{ fontSize: '22px', fontWeight: 700, color: s.color, margin: 0 }}>{s.val}</p>
                </div>
            ))}
        </div>

        {/* Task rows */}
        <div className="px-4 pt-3 pb-2 space-y-2">
            {[
                { label: "Design System v2", done: true,  badge: "S" },
                { label: "API Integration",  done: false, badge: "M" },
                { label: "User Research",    done: false, badge: "A" },
            ].map((task, i) => (
                <div key={i} className="flex items-center gap-3 px-3 py-2.5 rounded-lg"
                    style={{ backgroundColor: t.bgSoft, border: `1px solid ${t.border}` }}>
                    <div className="w-4 h-4 rounded flex-shrink-0 flex items-center justify-center"
                        style={{
                            border: `2px solid ${task.done ? t.success : t.border}`,
                            backgroundColor: task.done ? t.successSoft : 'transparent',
                        }}>
                        {task.done && (
                            <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: t.success }} />
                        )}
                    </div>
                    <span className="text-xs flex-1" style={{
                        color: task.done ? t.textMuted : t.textSec,
                        textDecoration: task.done ? 'line-through' : 'none',
                    }}>
                        {task.label}
                    </span>
                    <div className="w-5 h-5 rounded-full text-xs flex items-center justify-center font-bold"
                        style={{ backgroundColor: t.accentSoft, color: t.accent }}>
                        {task.badge}
                    </div>
                </div>
            ))}
        </div>

        {/* Progress bar */}
        <div className="px-4 pb-4">
            <div className="flex justify-between text-xs mb-1.5" style={{ color: t.textMuted }}>
                <span>Sprint Progress</span><span>67%</span>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ backgroundColor: t.border }}>
                <div className="h-full rounded-full" style={{ width: '67%', backgroundColor: t.accent }} />
            </div>
        </div>
    </div>
);

// ── Main Component ──────────────────────────────────────────────────
const LandingPage = () => {
    const [isDark, setIsDark] = useState(false);
    const [menuOpen, setMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const stored = localStorage.getItem('landing-theme');
        if (stored === 'dark') setIsDark(true);
    }, []);

    useEffect(() => {
        localStorage.setItem('landing-theme', isDark ? 'dark' : 'light');
    }, [isDark]);

    useEffect(() => {
        const handler = () => setScrolled(window.scrollY > 20);
        window.addEventListener('scroll', handler);
        return () => window.removeEventListener('scroll', handler);
    }, []);

    const t = isDark ? theme.dark : theme.light;

    const s = {
        page: { backgroundColor: t.bg, color: t.text, minHeight: '100vh', fontFamily: "'Outfit', sans-serif", transition: 'background 0.3s, color 0.3s' },
        nav: {
            position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
            backgroundColor: scrolled ? t.navBg : 'transparent',
            backdropFilter: scrolled ? 'blur(12px)' : 'none',
            borderBottom: scrolled ? `1px solid ${t.border}` : '1px solid transparent',
            transition: 'all 0.3s',
        },
        card: { backgroundColor: t.bgCard, border: `1px solid ${t.border}`, borderRadius: '16px' },
        btn: { backgroundColor: t.accent, color: t.accentText, borderRadius: '10px', fontWeight: 600, transition: 'all 0.2s', cursor: 'pointer' },
        btnOutline: { backgroundColor: 'transparent', color: t.text, border: `1px solid ${t.border}`, borderRadius: '10px', fontWeight: 600, transition: 'all 0.2s', cursor: 'pointer' },
        tag: { backgroundColor: t.accentSoft, color: t.accent, fontSize: '12px', fontWeight: 600, padding: '4px 12px', borderRadius: '100px', display: 'inline-block' },
    };

    return (
        <div style={s.page}>

            {/* ── Navbar ─────────────────────────────────────────── */}
            <nav style={s.nav}>
                <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 24px', height: '64px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ width: 32, height: 32, borderRadius: 10, backgroundColor: t.accent, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Zap size={16} color="#fff" />
                        </div>
                        <span style={{ fontWeight: 800, fontSize: '17px', color: t.text, letterSpacing: '-0.3px' }}>
                            ProjectFlow
                        </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '32px' }} className="hidden md:flex">
                        {['Features', 'Pricing', 'About'].map(link => (
                            <a key={link} href={`#${link.toLowerCase()}`}
                                style={{ fontSize: '14px', fontWeight: 500, color: t.textSec, textDecoration: 'none', transition: 'color 0.2s' }}
                                onMouseEnter={e => e.target.style.color = t.accent}
                                onMouseLeave={e => e.target.style.color = t.textSec}>
                                {link}
                            </a>
                        ))}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <button onClick={() => setIsDark(!isDark)}
                            style={{ width: 36, height: 36, borderRadius: 10, border: `1px solid ${t.border}`, backgroundColor: t.bgCard, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
                            {isDark ? <Sun size={15} color={t.textSec} /> : <Moon size={15} color={t.textSec} />}
                        </button>

                        <Link to="/login"
                            style={{ fontSize: '14px', fontWeight: 500, color: t.textSec, textDecoration: 'none', padding: '8px 14px', borderRadius: '10px', transition: 'all 0.2s' }}
                            onMouseEnter={e => { e.target.style.color = t.text; e.target.style.backgroundColor = t.bgSoft; }}
                            onMouseLeave={e => { e.target.style.color = t.textSec; e.target.style.backgroundColor = 'transparent'; }}>
                            Sign in
                        </Link>
                        <Link to="/register"
                            style={{ ...s.btn, fontSize: '14px', padding: '8px 18px', textDecoration: 'none', display: 'inline-block' }}
                            onMouseEnter={e => e.target.style.backgroundColor = t.accentHover}
                            onMouseLeave={e => e.target.style.backgroundColor = t.accent}>
                            Get started
                        </Link>

                        <button className="md:hidden" onClick={() => setMenuOpen(!menuOpen)}
                            style={{ width: 36, height: 36, borderRadius: 10, border: `1px solid ${t.border}`, backgroundColor: t.bgCard, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
                            {menuOpen ? <X size={16} color={t.text} /> : <Menu size={16} color={t.text} />}
                        </button>
                    </div>
                </div>

                {menuOpen && (
                    <div style={{ backgroundColor: t.bgCard, borderTop: `1px solid ${t.border}`, padding: '16px 24px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {['Features', 'Pricing', 'About'].map(link => (
                            <a key={link} href={`#${link.toLowerCase()}`} onClick={() => setMenuOpen(false)}
                                style={{ fontSize: '15px', fontWeight: 500, color: t.textSec, textDecoration: 'none', padding: '10px 0' }}>
                                {link}
                            </a>
                        ))}
                    </div>
                )}
            </nav>

            {/* ── Hero ───────────────────────────────────────────── */}
            <section style={{ paddingTop: '120px', paddingBottom: '80px', paddingLeft: '24px', paddingRight: '24px', backgroundColor: t.bg }}>
                <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
                    <div style={{ textAlign: 'center', marginBottom: '60px' }}>
                        <div style={{ ...s.tag, marginBottom: '20px' }}>
                            ✦ Trusted by 10,000+ teams worldwide
                        </div>
                        <h1 style={{ fontSize: 'clamp(36px, 6vw, 64px)', fontWeight: 800, letterSpacing: '-1.5px', lineHeight: 1.1, marginBottom: '20px', color: t.text }}>
                            Manage projects.<br />
                            <span style={{ color: t.accent }}>Ship faster.</span>
                        </h1>
                        <p style={{ fontSize: '18px', color: t.textSec, maxWidth: '520px', margin: '0 auto 36px', lineHeight: 1.7 }}>
                            The all-in-one workspace for modern teams to plan, track, and deliver great work — without the chaos.
                        </p>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', flexWrap: 'wrap' }}>
                            <Link to="/register"
                                style={{ ...s.btn, fontSize: '15px', padding: '12px 24px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '8px' }}
                                onMouseEnter={e => e.currentTarget.style.backgroundColor = t.accentHover}
                                onMouseLeave={e => e.currentTarget.style.backgroundColor = t.accent}>
                                Start managing projects <ArrowRight size={16} />
                            </Link>
                            <button
                                style={{ ...s.btnOutline, fontSize: '15px', padding: '12px 24px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}
                                onMouseEnter={e => { e.currentTarget.style.backgroundColor = t.bgSoft; }}
                                onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; }}>
                                View Demo <ChevronRight size={16} />
                            </button>
                        </div>
                        <div style={{ marginTop: '28px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', color: t.textMuted, fontSize: '13px' }}>
                            <CheckCircle size={14} color={t.success} />
                            No credit card &nbsp;·&nbsp;
                            <CheckCircle size={14} color={t.success} />
                            Free 14-day trial &nbsp;·&nbsp;
                            <CheckCircle size={14} color={t.success} />
                            Cancel anytime
                        </div>
                    </div>

                    {/* Dashboard Preview */}
                    <div style={{ maxWidth: '680px', margin: '0 auto' }}>
                        <DashboardPreview t={t} />
                    </div>
                </div>
            </section>

            {/* ── Stats ──────────────────────────────────────────── */}
            <section style={{ borderTop: `1px solid ${t.border}`, borderBottom: `1px solid ${t.border}`, backgroundColor: t.bgSoft }}>
                <div style={{ maxWidth: '900px', margin: '0 auto', padding: '40px 24px', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
                    {[
                        { val: '10K+', label: 'Teams using ProjectFlow' },
                        { val: '2M+',  label: 'Tasks completed monthly' },
                        { val: '99.9%', label: 'Uptime guaranteed' },
                    ].map((s2, i) => (
                        <div key={i} style={{ textAlign: 'center', padding: '16px' }}>
                            <p style={{ fontSize: '32px', fontWeight: 800, color: t.accent, letterSpacing: '-1px', marginBottom: '4px' }}>{s2.val}</p>
                            <p style={{ fontSize: '13px', color: t.textMuted }}>{s2.label}</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* ── Features ───────────────────────────────────────── */}
            <section id="features" style={{ padding: '96px 24px', backgroundColor: t.bg }}>
                <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
                    <div style={{ textAlign: 'center', marginBottom: '60px' }}>
                        <div style={{ ...s.tag, marginBottom: '16px' }}>Features</div>
                        <h2 style={{ fontSize: 'clamp(28px, 4vw, 42px)', fontWeight: 800, letterSpacing: '-1px', color: t.text, marginBottom: '14px' }}>
                            Everything you need to ship
                        </h2>
                        <p style={{ fontSize: '16px', color: t.textSec, maxWidth: '440px', margin: '0 auto' }}>
                            A complete toolkit built for teams that move fast and care about quality.
                        </p>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
                        {features.map((f, i) => (
                            <div key={i} style={{ ...s.card, padding: '28px', transition: 'all 0.2s', cursor: 'default' }}
                                onMouseEnter={e => { e.currentTarget.style.borderColor = t.accent; e.currentTarget.style.boxShadow = `0 0 0 1px ${t.accent}22`; }}
                                onMouseLeave={e => { e.currentTarget.style.borderColor = t.border; e.currentTarget.style.boxShadow = 'none'; }}>
                                <div style={{ width: 44, height: 44, borderRadius: 12, backgroundColor: t.accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                                    <f.icon size={20} color={t.accent} />
                                </div>
                                <h3 style={{ fontSize: '15px', fontWeight: 700, color: t.text, marginBottom: '8px' }}>{f.title}</h3>
                                <p style={{ fontSize: '14px', color: t.textSec, lineHeight: 1.65 }}>{f.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── Workflow ───────────────────────────────────────── */}
            <section style={{ padding: '96px 24px', backgroundColor: t.bgSoft, borderTop: `1px solid ${t.border}` }}>
                <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
                    <div style={{ textAlign: 'center', marginBottom: '60px' }}>
                        <div style={{ ...s.tag, marginBottom: '16px' }}>How it works</div>
                        <h2 style={{ fontSize: 'clamp(28px, 4vw, 42px)', fontWeight: 800, letterSpacing: '-1px', color: t.text, marginBottom: '14px' }}>
                            From idea to delivery
                        </h2>
                        <p style={{ fontSize: '16px', color: t.textSec, maxWidth: '420px', margin: '0 auto' }}>
                            A simple workflow that scales from solo projects to enterprise teams.
                        </p>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '24px' }}>
                        {workflow.map((w, i) => (
                            <div key={i} style={{ ...s.card, padding: '28px', position: 'relative', overflow: 'hidden' }}>
                                <span style={{ position: 'absolute', top: '16px', right: '16px', fontSize: '36px', fontWeight: 900, color: t.accentSoft, lineHeight: 1 }}>{w.step}</span>
                                <div style={{ width: 44, height: 44, borderRadius: 12, backgroundColor: t.accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                                    <w.icon size={20} color={t.accent} />
                                </div>
                                <h3 style={{ fontSize: '15px', fontWeight: 700, color: t.text, marginBottom: '8px' }}>{w.title}</h3>
                                <p style={{ fontSize: '14px', color: t.textSec, lineHeight: 1.65 }}>{w.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── Testimonials ───────────────────────────────────── */}
            <section style={{ padding: '96px 24px', backgroundColor: t.bg, borderTop: `1px solid ${t.border}` }}>
                <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
                    <div style={{ textAlign: 'center', marginBottom: '60px' }}>
                        <div style={{ ...s.tag, marginBottom: '16px' }}>Testimonials</div>
                        <h2 style={{ fontSize: 'clamp(28px, 4vw, 42px)', fontWeight: 800, letterSpacing: '-1px', color: t.text }}>
                            Loved by teams everywhere
                        </h2>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px' }}>
                        {testimonials.map((t2, i) => (
                            <div key={i} style={{ ...s.card, padding: '28px' }}>
                                <div style={{ display: 'flex', marginBottom: '14px', gap: '2px' }}>
                                    {[...Array(t2.stars)].map((_, j) => (
                                        <Star key={j} size={14} fill={t.warning} color={t.warning} />
                                    ))}
                                </div>
                                <p style={{ fontSize: '15px', color: t.textSec, lineHeight: 1.7, marginBottom: '20px' }}>
                                    "{t2.text}"
                                </p>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                    <div style={{ width: 38, height: 38, borderRadius: '50%', backgroundColor: t.accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '13px', fontWeight: 700, color: t.accent, flexShrink: 0 }}>
                                        {t2.avatar}
                                    </div>
                                    <div>
                                        <p style={{ fontSize: '14px', fontWeight: 700, color: t.text, marginBottom: '2px' }}>{t2.name}</p>
                                        <p style={{ fontSize: '12px', color: t.textMuted }}>{t2.role}</p>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── CTA ────────────────────────────────────────────── */}
            <section style={{ padding: '96px 24px', backgroundColor: t.accent }}>
                <div style={{ maxWidth: '640px', margin: '0 auto', textAlign: "center" }}>
                    <Shield size={36} color="rgba(255,255,255,0.6)" style={{ margin: '0 auto 20px' }} />
                    <h2 style={{ fontSize: 'clamp(28px, 4vw, 42px)', fontWeight: 800, color: '#fff', letterSpacing: '-1px', marginBottom: '14px' }}>
                        Ready to ship great work?
                    </h2>
                    <p style={{ fontSize: '16px', color: 'rgba(255,255,255,0.7)', marginBottom: '32px', lineHeight: 1.7 }}>
                        Join thousands of teams who already deliver faster with ProjectFlow. Free forever for small teams.
                    </p>
                    <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', flexWrap: 'wrap' }}>
                        <Link to="/register"
                            style={{ backgroundColor: '#fff', color: t.accent, fontSize: '15px', fontWeight: 700, padding: '12px 24px', borderRadius: '10px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '8px', transition: 'opacity 0.2s' }}
                            onMouseEnter={e => e.currentTarget.style.opacity = '0.92'}
                            onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
                            Create free account <ArrowRight size={16} />
                        </Link>
                        <Link to="/login"
                            style={{ backgroundColor: 'rgba(255,255,255,0.12)', color: '#fff', fontSize: '15px', fontWeight: 600, padding: '12px 24px', borderRadius: '10px', textDecoration: 'none', border: '1px solid rgba(255,255,255,0.2)', transition: 'background 0.2s' }}
                            onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.18)'}
                            onMouseLeave={e => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.12)'}>
                            Sign in
                        </Link>
                    </div>
                </div>
            </section>

            {/* ── Footer ─────────────────────────────────────────── */}
            <footer style={{ backgroundColor: t.bgSoft, borderTop: `1px solid ${t.border}`, padding: '48px 24px 32px' }}>
                <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: '40px', marginBottom: '40px' }} className="footer-grid">
                        <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
                                <div style={{ width: 30, height: 30, borderRadius: 8, backgroundColor: t.accent, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                    <Zap size={14} color="#fff" />
                                </div>
                                <span style={{ fontWeight: 800, fontSize: '16px', color: t.text }}>ProjectFlow</span>
                            </div>
                            <p style={{ fontSize: '13px', color: t.textMuted, lineHeight: 1.7, maxWidth: '240px' }}>
                                The modern project management platform for teams that ship fast.
                            </p>
                        </div>
                        {[
                            { title: 'Product', links: ['Features', 'Pricing', 'Changelog', 'Roadmap'] },
                            { title: 'Company', links: ['About', 'Blog', 'Careers', 'Contact'] },
                            { title: 'Legal',   links: ['Privacy', 'Terms', 'Security', 'Cookies'] },
                        ].map((col) => (
                            <div key={col.title}>
                                <p style={{ fontSize: '12px', fontWeight: 700, color: t.textMuted, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>{col.title}</p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                    {col.links.map(link => (
                                        <a key={link} href="#"
                                            style={{ fontSize: '13px', color: t.textSec, textDecoration: 'none', transition: 'color 0.2s' }}
                                            onMouseEnter={e => e.target.style.color = t.accent}
                                            onMouseLeave={e => e.target.style.color = t.textSec}>
                                            {link}
                                        </a>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                    <div style={{ borderTop: `1px solid ${t.border}`, paddingTop: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                        <p style={{ fontSize: '12px', color: t.textMuted }}>
                            © {new Date().getFullYear()} ProjectFlow. All rights reserved.
                        </p>
                        <p style={{ fontSize: '12px', color: t.textMuted }}>
                            Built for teams that care about quality.
                        </p>
                    </div>
                </div>
            </footer>

            <style>{`
                @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&display=swap');
                * { box-sizing: border-box; margin: 0; padding: 0; }
                .hidden { display: none; }
                @media (min-width: 768px) { .hidden.md\\:flex { display: flex !important; } .md\\:hidden { display: none !important; } }
                @media (max-width: 767px) { .footer-grid { grid-template-columns: 1fr 1fr !important; } }
                a { transition: all 0.2s; }
            `}</style>
        </div>
    );
};

export default LandingPage;