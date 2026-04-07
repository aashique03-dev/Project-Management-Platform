import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import {
    CheckCircle, LayoutDashboard, Users, Calendar,
    BarChart2, Bell, ArrowRight, Zap, Shield, Star,
    Menu, X, ChevronRight, Target, Clock, TrendingUp,
    Layers, GitBranch, Circle
} from "lucide-react";

/* ── Design tokens (self-contained for landing page) ───────────── */
const C = {
    bg:          "#0A0A0F",
    bgAlt:       "#12121A",
    bgElevated:  "#1A1A24",
    fg:          "#FAFAFA",
    fgMuted:     "#71717A",
    fgSubtle:    "#3F3F46",
    accent:      "#F59E0B",
    accentFg:    "#0A0A0F",
    accentMuted: "rgba(245,158,11,0.10)",
    accentGlow:  "rgba(245,158,11,0.22)",
    border:      "rgba(255,255,255,0.07)",
    borderHover: "rgba(255,255,255,0.13)",
};

/* ── Static data ───────────────────────────────────────────────── */
const features = [
    { icon: LayoutDashboard, title: "Smart Dashboard",      desc: "Real-time overview of all projects, deadlines, and team activity in one unified view." },
    { icon: Users,           title: "Team Collaboration",   desc: "Assign tasks, set roles, comment inline, and keep everyone aligned without the noise." },
    { icon: CheckCircle,     title: "Task Management",      desc: "Create, prioritize, and track tasks with custom statuses, tags, and due dates." },
    { icon: BarChart2,       title: "Analytics & Reports",  desc: "Visualize productivity trends, bottlenecks, and team performance with clear charts." },
    { icon: Calendar,        title: "Timeline & Calendar",  desc: "See your entire project roadmap in a Gantt-style view with drag-and-drop scheduling." },
    { icon: Bell,            title: "Smart Notifications",  desc: "Never miss a deadline. Get intelligent alerts for blockers, mentions, and updates." },
];

const workflow = [
    { step: "01", icon: Target,    title: "Define your project", desc: "Set goals, milestones, and invite your team in minutes." },
    { step: "02", icon: Layers,    title: "Break it into tasks",  desc: "Create task lists, assign owners, and set priorities." },
    { step: "03", icon: GitBranch, title: "Track in real time",   desc: "Monitor progress on a live board as work moves forward." },
    { step: "04", icon: TrendingUp,title: "Ship and improve",     desc: "Analyse what worked, iterate fast, and deliver on time." },
];

const testimonials = [
    { name: "Sarah Chen",   role: "Head of Product, Vercel", text: "This replaced Jira, Notion, and Slack threads for us. Our team ships 40% faster.", stars: 5, initials: "SC" },
    { name: "Marcus Webb",  role: "Engineering Lead, Stripe", text: "The cleanest project tool I've used. It stays out of the way and just works.",    stars: 5, initials: "MW" },
    { name: "Aisha Patel",  role: "Founder, Luminary",        text: "We replaced 3 tools with this one. Onboarding took 10 minutes. Team loved it.",    stars: 5, initials: "AP" },
];

const stats = [
    { val: "10K+",  label: "Teams worldwide"       },
    { val: "2M+",   label: "Tasks completed monthly"},
    { val: "99.9%", label: "Uptime guaranteed"      },
];

/* ── Pricing plans ─────────────────────────────────────────────── */
const plans = [
    {
        name: "Free",
        price: "$0",
        period: "forever",
        desc: "Perfect for individuals and small teams getting started.",
        features: [
            "Up to 3 projects",
            "5 team members",
            "Basic task management",
            "1 GB storage",
            "Community support",
        ],
        cta: "Get started",
        ctaLink: "/register",
        popular: false,
    },
    {
        name: "Pro",
        price: "$12",
        period: "per user / month",
        desc: "Everything you need to run a growing team with confidence.",
        features: [
            "Unlimited projects",
            "Up to 25 team members",
            "Advanced analytics & reports",
            "Timeline & Gantt view",
            "20 GB storage",
            "Priority email support",
        ],
        cta: "Start free trial",
        ctaLink: "/register",
        popular: true,
    },
    {
        name: "Enterprise",
        price: "$39",
        period: "per user / month",
        desc: "Advanced security, controls, and support for large organisations.",
        features: [
            "Unlimited everything",
            "Unlimited team members",
            "SSO & advanced permissions",
            "Custom integrations & API",
            "Unlimited storage",
            "Dedicated account manager",
            "SLA & 99.99% uptime",
        ],
        cta: "Contact sales",
        ctaLink: "/register",
        popular: false,
    },
];

/* ── Shared style helpers ──────────────────────────────────────── */
const card = {
    background:    `rgba(26,26,36,0.55)`,
    backdropFilter:"blur(10px)",
    WebkitBackdropFilter:"blur(10px)",
    border:        `1px solid ${C.border}`,
    borderRadius:  12,
};

const btnPrimary = {
    display:"inline-flex", alignItems:"center", gap:"0.5rem",
    padding:"0.7rem 1.5rem", borderRadius:8,
    background: C.accent, color: C.accentFg,
    fontWeight:600, fontSize:"0.9rem",
    border:"none", cursor:"pointer", textDecoration:"none",
    transition:"all 200ms ease-out",
    fontFamily:"'Inter', sans-serif",
    letterSpacing:"0.005em",
    whiteSpace:"nowrap",
};
const btnOutline = {
    ...btnPrimary,
    background:"transparent", color: C.fg,
    border:`1px solid ${C.borderHover}`,
};

/* ── Dashboard preview widget ──────────────────────────────────── */
const DashPreview = () => (
    <div style={{ ...card, overflow:"hidden", maxWidth:640, margin:"0 auto" }}>
        {/* Traffic lights */}
        <div style={{ display:"flex", alignItems:"center", gap:8, padding:"10px 14px", background:"rgba(255,255,255,0.03)", borderBottom:`1px solid ${C.border}` }}>
            {["#FF5F57","#FEBC2E","#28C840"].map((c,i)=>(
                <div key={i} style={{ width:10, height:10, borderRadius:"50%", background:c }} />
            ))}
            <div style={{ flex:1, height:6, borderRadius:4, background:C.border, marginLeft:8 }} />
        </div>

        {/* Stats row */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:1, background:C.border }}>
            {[
                { label:"Projects",   val:"12",  color:C.accent },
                { label:"Done",       val:"84%", color:"#34d399" },
                { label:"Overdue",    val:"3",   color:"#f87171" },
            ].map((s,i)=>(
                <div key={i} style={{ background:C.bgAlt, padding:"12px 14px" }}>
                    <p style={{ fontSize:11, color:C.fgMuted, marginBottom:4 }}>{s.label}</p>
                    <p style={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:22, fontWeight:700, color:s.color }}>{s.val}</p>
                </div>
            ))}
        </div>

        {/* Task rows */}
        <div style={{ padding:"10px 12px", display:"flex", flexDirection:"column", gap:6 }}>
            {[
                { title:"Design System v2", done:true,  badge:"S", badgeColor:"#34d399" },
                { title:"API Integration",  done:false, badge:"M", badgeColor:C.accent   },
                { title:"User Research",    done:false, badge:"A", badgeColor:"#60a5fa"  },
            ].map((t,i)=>(
                <div key={i} style={{
                    display:"flex", alignItems:"center", gap:10,
                    padding:"9px 12px", borderRadius:8,
                    background:"rgba(255,255,255,0.03)",
                    border:`1px solid ${C.border}`
                }}>
                    <div style={{
                        width:14, height:14, borderRadius:4, flexShrink:0,
                        border:`2px solid ${t.done ? "#34d399" : C.border}`,
                        background: t.done ? "rgba(52,211,153,0.15)" : "transparent",
                        display:"flex", alignItems:"center", justifyContent:"center"
                    }}>
                        {t.done && <div style={{ width:6, height:6, borderRadius:2, background:"#34d399" }} />}
                    </div>
                    <span style={{
                        flex:1, fontSize:12, color: t.done ? C.fgMuted : C.fg,
                        textDecoration: t.done ? "line-through" : "none"
                    }}>{t.title}</span>
                    <div style={{
                        width:20, height:20, borderRadius:"50%",
                        background:`rgba(245,158,11,0.12)`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        fontSize:10, fontWeight:700, color:t.badgeColor
                    }}>{t.badge}</div>
                </div>
            ))}
        </div>

        {/* Progress */}
        <div style={{ padding:"4px 12px 12px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                <span style={{ fontSize:11, color:C.fgMuted, fontFamily:"'JetBrains Mono',monospace" }}>Sprint Progress</span>
                <span style={{ fontSize:11, color:C.accent,  fontFamily:"'JetBrains Mono',monospace" }}>67%</span>
            </div>
            <div style={{ height:4, borderRadius:9999, background:C.border, overflow:"hidden" }}>
                <div style={{ height:"100%", width:"67%", borderRadius:9999, background:C.accent }} />
            </div>
        </div>
    </div>
);

/* ── Pricing section component ─────────────────────────────────── */
const PricingSection = () => (
    <section id="pricing" style={{ padding:"6rem 1.5rem", borderTop:`1px solid ${C.border}`, position:"relative", zIndex:1 }}>
        <div style={{ maxWidth:1100, margin:"0 auto" }}>
            <SectionHeader
                label="Pricing"
                title="Simple, transparent pricing"
                sub="Start free, upgrade when you need more. No hidden fees, no surprises."
            />

            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))", gap:14, alignItems:"start" }}>
                {plans.map((plan, i) => (
                    <div key={i} style={{
                        ...card,
                        padding:"2rem",
                        position:"relative",
                        border: plan.popular
                            ? `1px solid rgba(245,158,11,0.45)`
                            : `1px solid ${C.border}`,
                        transition:"all 300ms ease-out",
                    }}
                        onMouseEnter={e=>{
                            e.currentTarget.style.transform="translateY(-3px)";
                            e.currentTarget.style.boxShadow=`0 12px 36px rgba(0,0,0,0.4)`;
                        }}
                        onMouseLeave={e=>{
                            e.currentTarget.style.transform="none";
                            e.currentTarget.style.boxShadow="none";
                        }}
                    >
                        {/* Popular badge */}
                        {plan.popular && (
                            <div style={{
                                position:"absolute", top:-1, left:"50%", transform:"translateX(-50%)",
                                background:C.accent, color:C.accentFg,
                                fontSize:"0.65rem", fontWeight:700, letterSpacing:"0.08em",
                                textTransform:"uppercase", padding:"3px 14px",
                                borderRadius:"0 0 8px 8px",
                                fontFamily:"'JetBrains Mono',monospace",
                            }}>
                                Most popular
                            </div>
                        )}

                        {/* Plan name */}
                        <p style={{
                            fontFamily:"'JetBrains Mono',monospace",
                            fontSize:"0.7rem", fontWeight:600, letterSpacing:"0.1em",
                            textTransform:"uppercase", color: plan.popular ? C.accent : C.fgMuted,
                            marginBottom:12,
                        }}>
                            {plan.name}
                        </p>

                        {/* Price */}
                        <div style={{ display:"flex", alignItems:"baseline", gap:6, marginBottom:6 }}>
                            <span style={{
                                fontFamily:"'Space Grotesk',sans-serif",
                                fontSize:"clamp(2rem,5vw,2.75rem)",
                                fontWeight:800, letterSpacing:"-0.04em",
                                color: plan.popular ? C.accent : C.fg,
                            }}>
                                {plan.price}
                            </span>
                            <span style={{ fontSize:"0.78rem", color:C.fgMuted }}>/{plan.period}</span>
                        </div>

                        {/* Description */}
                        <p style={{ fontSize:"0.82rem", color:C.fgMuted, lineHeight:1.65, marginBottom:24 }}>
                            {plan.desc}
                        </p>

                        {/* Divider */}
                        <div style={{ height:1, background:C.border, marginBottom:20 }} />

                        {/* Features list */}
                        <ul style={{ listStyle:"none", padding:0, margin:"0 0 28px", display:"flex", flexDirection:"column", gap:10 }}>
                            {plan.features.map((feat, j) => (
                                <li key={j} style={{ display:"flex", alignItems:"center", gap:10, fontSize:"0.83rem", color:C.fg }}>
                                    <CheckCircle
                                        size={14}
                                        strokeWidth={2}
                                        style={{ color: plan.popular ? C.accent : "#34d399", flexShrink:0 }}
                                    />
                                    {feat}
                                </li>
                            ))}
                        </ul>

                        {/* CTA */}
                        <Link
                            to={plan.ctaLink}
                            style={{
                                ...(plan.popular ? btnPrimary : btnOutline),
                                width:"100%",
                                justifyContent:"center",
                                boxSizing:"border-box",
                            }}
                            onMouseEnter={e=>{
                                if(plan.popular){
                                    e.currentTarget.style.filter="brightness(1.1)";
                                    e.currentTarget.style.boxShadow=`0 0 22px ${C.accentGlow}`;
                                } else {
                                    e.currentTarget.style.background="rgba(255,255,255,0.05)";
                                }
                            }}
                            onMouseLeave={e=>{
                                e.currentTarget.style.filter="none";
                                e.currentTarget.style.boxShadow="none";
                                e.currentTarget.style.background= plan.popular ? C.accent : "transparent";
                            }}
                        >
                            {plan.cta} <ArrowRight size={14} strokeWidth={2} />
                        </Link>
                    </div>
                ))}
            </div>

            {/* Bottom note */}
            <p style={{ textAlign:"center", fontSize:"0.78rem", color:C.fgMuted, marginTop:28 }}>
                All plans include a 14-day free trial. No credit card required.
            </p>
        </div>
    </section>
);

/* ── Main component ────────────────────────────────────────────── */
const LandingPage = () => {
    const [menuOpen, setMenuOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);

    useEffect(() => {
        const handler = () => setScrolled(window.scrollY > 24);
        window.addEventListener("scroll", handler);
        return () => window.removeEventListener("scroll", handler);
    }, []);

    return (
        <div style={{ background:C.bg, color:C.fg, minHeight:"100vh", fontFamily:"'Inter',sans-serif", overflowX:"hidden" }}>

            {/* ── Fixed ambient orbs ─────────────────────────────── */}
            <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0, overflow:"hidden" }}>
                <div style={{
                    position:"absolute", width:700, height:700, borderRadius:"50%",
                    background:C.accent, filter:"blur(140px)", opacity:0.028,
                    top:-200, left:"50%", transform:"translateX(-50%)"
                }} />
                <div style={{
                    position:"absolute", width:500, height:500, borderRadius:"50%",
                    background:"#6366F1", filter:"blur(130px)", opacity:0.018,
                    bottom:-200, right:-100
                }} />
            </div>

            {/* ── Navbar ─────────────────────────────────────────── */}
            <nav style={{
                position:"fixed", top:0, left:0, right:0, zIndex:100,
                background: scrolled ? "rgba(10,10,15,0.88)" : "transparent",
                backdropFilter: scrolled ? "blur(14px)" : "none",
                WebkitBackdropFilter: scrolled ? "blur(14px)" : "none",
                borderBottom: scrolled ? `1px solid ${C.border}` : "1px solid transparent",
                transition:"all 300ms ease-out",
            }}>
                <div style={{ maxWidth:1100, margin:"0 auto", padding:"0 1.5rem", height:60, display:"flex", alignItems:"center", justifyContent:"space-between" }}>

                    {/* Logo */}
                    <div style={{ display:"flex", alignItems:"center", gap:9 }}>
                        <div style={{
                            width:30, height:30, borderRadius:8,
                            background:C.accent, display:"flex", alignItems:"center", justifyContent:"center",
                            boxShadow:`0 0 18px ${C.accentGlow}`
                        }}>
                            <Zap size={15} color={C.accentFg} strokeWidth={2.5} />
                        </div>
                        <span style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:700, fontSize:"1rem", letterSpacing:"-0.02em", color:C.fg }}>
                            ProjectFlow
                        </span>
                    </div>

                    {/* Desktop links — BUG FIX: nav links now correctly point to #features, #pricing, #about */}
                    <div style={{ display:"flex", alignItems:"center", gap:28 }} className="lp-desktop-nav">
                        {[
                            { label:"Features", href:"#features" },
                            { label:"Pricing",  href:"#pricing"  },
                            { label:"About",    href:"#about"    },
                        ].map(l => (
                            <a key={l.label} href={l.href} style={{
                                fontSize:"0.875rem", fontWeight:450, color:C.fgMuted,
                                textDecoration:"none", transition:"color 200ms",
                                letterSpacing:"0.005em"
                            }}
                                onMouseEnter={e=>e.target.style.color=C.fg}
                                onMouseLeave={e=>e.target.style.color=C.fgMuted}
                            >{l.label}</a>
                        ))}
                    </div>

                    {/* CTA group */}
                    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                        <Link to="/login" className="lp-desktop-nav" style={{
                            fontSize:"0.875rem", fontWeight:450, color:C.fgMuted,
                            textDecoration:"none", padding:"0.45rem 0.875rem",
                            borderRadius:8, transition:"all 200ms"
                        }}
                            onMouseEnter={e=>{e.currentTarget.style.color=C.fg;e.currentTarget.style.background="rgba(255,255,255,0.05)"}}
                            onMouseLeave={e=>{e.currentTarget.style.color=C.fgMuted;e.currentTarget.style.background="transparent"}}
                        >Sign in</Link>

                        <Link to="/register" style={{
                            ...btnPrimary,
                            padding:"0.45rem 1.1rem", fontSize:"0.85rem",
                            boxShadow:`0 0 0px ${C.accentGlow}`
                        }}
                            onMouseEnter={e=>{e.currentTarget.style.filter="brightness(1.1)";e.currentTarget.style.boxShadow=`0 0 22px ${C.accentGlow}`}}
                            onMouseLeave={e=>{e.currentTarget.style.filter="none";e.currentTarget.style.boxShadow="none"}}
                        >Get started</Link>

                        {/* Mobile hamburger */}
                        <button
                            className="lp-mobile-only"
                            onClick={() => setMenuOpen(!menuOpen)}
                            style={{ background:"none", border:`1px solid ${C.border}`, borderRadius:8, width:34, height:34, display:"none", alignItems:"center", justifyContent:"center", cursor:"pointer" }}
                        >
                            {menuOpen ? <X size={16} color={C.fg} /> : <Menu size={16} color={C.fg} />}
                        </button>
                    </div>
                </div>

                {/* Mobile drawer */}
                {menuOpen && (
                    <div style={{ background:C.bgAlt, borderTop:`1px solid ${C.border}`, padding:"1rem 1.5rem", display:"flex", flexDirection:"column", gap:4 }}>
                        {[
                            { label:"Features", href:"#features" },
                            { label:"Pricing",  href:"#pricing"  },
                            { label:"About",    href:"#about"    },
                        ].map(l => (
                            <a key={l.label} href={l.href} onClick={()=>setMenuOpen(false)}
                                style={{ fontSize:"1rem", color:C.fgMuted, textDecoration:"none", padding:"0.625rem 0" }}
                            >{l.label}</a>
                        ))}
                        <div style={{ height:1, background:C.border, margin:"0.5rem 0" }} />
                        <Link to="/login" style={{ fontSize:"1rem", color:C.fg, textDecoration:"none", padding:"0.5rem 0" }}>Sign in</Link>
                        <Link to="/register" style={{ ...btnPrimary, justifyContent:"center", marginTop:"0.5rem" }}>Get started</Link>
                    </div>
                )}
            </nav>

            {/* ── Hero ───────────────────────────────────────────── */}
            <section style={{ paddingTop:140, paddingBottom:100, paddingLeft:24, paddingRight:24, position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:1100, margin:"0 auto" }}>

                    {/* Badge */}
                    <div style={{ textAlign:"center", marginBottom:28 }}>
                        <span style={{
                            display:"inline-flex", alignItems:"center", gap:8,
                            background:C.accentMuted,
                            border:`1px solid rgba(245,158,11,0.22)`,
                            borderRadius:9999, padding:"0.3rem 0.875rem",
                            fontSize:"0.75rem", fontWeight:600, color:C.accent,
                            fontFamily:"'JetBrains Mono',monospace", letterSpacing:"0.04em",
                        }}>
                            <span style={{ width:6, height:6, borderRadius:"50%", background:C.accent, boxShadow:`0 0 8px ${C.accentGlow}`, animation:"lp-pulse 2s ease-in-out infinite", flexShrink:0 }} />
                            TRUSTED BY 10,000+ TEAMS WORLDWIDE
                        </span>
                    </div>

                    {/* Headline */}
                    <div style={{ textAlign:"center", marginBottom:36 }}>
                        <h1 style={{
                            fontFamily:"'Space Grotesk',sans-serif",
                            fontSize:"clamp(2.4rem, 6vw, 4.5rem)",
                            fontWeight:800, letterSpacing:"-0.04em", lineHeight:1.06,
                            color:C.fg, marginBottom:0,
                        }}>
                            Manage projects.<br />
                            <span style={{ color:C.accent, textShadow:`0 0 40px ${C.accentGlow}` }}>Ship faster.</span>
                        </h1>

                        <p style={{
                            fontSize:"clamp(1rem, 2vw, 1.15rem)",
                            color:C.fgMuted, lineHeight:1.75,
                            maxWidth:480, margin:"20px auto 0",
                        }}>
                            The all-in-one workspace for modern teams to plan, track, and deliver great work — without the chaos.
                        </p>
                    </div>

                    {/* CTA buttons */}
                    <div style={{ display:"flex", justifyContent:"center", gap:12, flexWrap:"wrap", marginBottom:20 }}>
                        <Link to="/register" style={btnPrimary}
                            onMouseEnter={e=>{e.currentTarget.style.filter="brightness(1.1)";e.currentTarget.style.boxShadow=`0 0 28px ${C.accentGlow}`}}
                            onMouseLeave={e=>{e.currentTarget.style.filter="none";e.currentTarget.style.boxShadow="none"}}
                        >
                            Start for free <ArrowRight size={15} strokeWidth={2} />
                        </Link>
                        <button style={btnOutline}
                            onMouseEnter={e=>{e.currentTarget.style.background="rgba(255,255,255,0.05)";e.currentTarget.style.borderColor=C.borderHover}}
                            onMouseLeave={e=>{e.currentTarget.style.background="transparent";e.currentTarget.style.borderColor=C.borderHover}}
                        >
                            View demo <ChevronRight size={15} strokeWidth={2} />
                        </button>
                    </div>

                    {/* Trust line */}
                    <div style={{ display:"flex", justifyContent:"center", alignItems:"center", gap:18, marginBottom:60, flexWrap:"wrap" }}>
                        {["No credit card","Free 14-day trial","Cancel anytime"].map(t => (
                            <span key={t} style={{ display:"flex", alignItems:"center", gap:6, fontSize:"0.78rem", color:C.fgMuted }}>
                                <CheckCircle size={13} strokeWidth={2} style={{ color:"#34d399" }} />
                                {t}
                            </span>
                        ))}
                    </div>

                    {/* Dashboard preview */}
                    <DashPreview />
                </div>
            </section>

            {/* ── Stats ──────────────────────────────────────────── */}
            <section style={{ borderTop:`1px solid ${C.border}`, borderBottom:`1px solid ${C.border}`, background:C.bgAlt, position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:800, margin:"0 auto", padding:"2.5rem 1.5rem", display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:24 }}>
                    {stats.map((s,i) => (
                        <div key={i} style={{ textAlign:"center" }}>
                            <p style={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:"clamp(1.75rem,4vw,2.25rem)", fontWeight:800, color:C.accent, letterSpacing:"-0.04em", marginBottom:4 }}>
                                {s.val}
                            </p>
                            <p style={{ fontSize:"0.8rem", color:C.fgMuted }}>{s.label}</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* ── Features ───────────────────────────────────────── */}
            <section id="features" style={{ padding:"6rem 1.5rem", position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:1100, margin:"0 auto" }}>
                    <SectionHeader
                        label="Features"
                        title="Everything you need to ship"
                        sub="A complete toolkit built for teams that move fast and care about quality."
                    />
                    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(300px,1fr))", gap:14 }}>
                        {features.map((f,i) => (
                            <div key={i} style={{ ...card, padding:"1.625rem", transition:"all 300ms ease-out", cursor:"default" }}
                                onMouseEnter={e=>{e.currentTarget.style.borderColor="rgba(245,158,11,0.22)";e.currentTarget.style.transform="translateY(-2px)";e.currentTarget.style.boxShadow=`0 10px 30px rgba(0,0,0,0.35)`}}
                                onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.transform="none";e.currentTarget.style.boxShadow="none"}}
                            >
                                <div style={{ width:40, height:40, borderRadius:10, background:C.accentMuted, display:"flex", alignItems:"center", justifyContent:"center", marginBottom:14 }}>
                                    <f.icon size={18} strokeWidth={1.5} color={C.accent} />
                                </div>
                                <h3 style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:600, fontSize:"0.95rem", letterSpacing:"-0.01em", color:C.fg, marginBottom:8 }}>
                                    {f.title}
                                </h3>
                                <p style={{ fontSize:"0.83rem", color:C.fgMuted, lineHeight:1.7 }}>{f.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── How it works ───────────────────────────────────── */}
            <section id="how-it-works" style={{ padding:"6rem 1.5rem", background:C.bgAlt, borderTop:`1px solid ${C.border}`, position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:1100, margin:"0 auto" }}>
                    <SectionHeader
                        label="How it works"
                        title="From idea to delivery"
                        sub="A simple workflow that scales from solo projects to enterprise teams."
                    />
                    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))", gap:14 }}>
                        {workflow.map((w,i) => (
                            <div key={i} style={{ ...card, padding:"1.625rem", position:"relative", overflow:"hidden" }}>
                                {/* Step number watermark */}
                                <span style={{
                                    position:"absolute", top:14, right:16,
                                    fontFamily:"'Space Grotesk',sans-serif",
                                    fontSize:42, fontWeight:900,
                                   color: "rgb(245,158,11)",opacity: 0.4, lineHeight:1, userSelect:"none"
                                }}>{w.step}</span>
                                <div style={{ width:40, height:40, borderRadius:10, background:C.accentMuted, display:"flex", alignItems:"center", justifyContent:"center", marginBottom:14 }}>
                                    <w.icon size={18} strokeWidth={1.5} color={C.accent} />
                                </div>
                                <h3 style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:600, fontSize:"0.95rem", letterSpacing:"-0.01em", color:C.fg, marginBottom:8 }}>
                                    {w.title}
                                </h3>
                                <p style={{ fontSize:"0.83rem", color:C.fgMuted, lineHeight:1.7 }}>{w.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── Pricing ────────────────────────────────────────── */}
            <PricingSection />

            {/* ── Testimonials ───────────────────────────────────── */}
            <section id="about" style={{ padding:"6rem 1.5rem", borderTop:`1px solid ${C.border}`, position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:1100, margin:"0 auto" }}>
                    <SectionHeader
                        label="Testimonials"
                        title="Loved by teams everywhere"
                        sub={null}
                    />
                    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(300px,1fr))", gap:14 }}>
                        {testimonials.map((t,i) => (
                            <div key={i} style={{ ...card, padding:"1.625rem" }}>
                                {/* Stars */}
                                <div style={{ display:"flex", gap:3, marginBottom:14 }}>
                                    {[...Array(t.stars)].map((_,j) => (
                                        <Star key={j} size={13} fill={C.accent} color={C.accent} />
                                    ))}
                                </div>
                                {/* Quote line */}
                                <div style={{ width:28, height:2, background:C.accent, borderRadius:9999, marginBottom:14, boxShadow:`0 0 10px ${C.accentGlow}` }} />
                                <p style={{ fontSize:"0.88rem", color:C.fgMuted, lineHeight:1.75, marginBottom:20 }}>
                                    "{t.text}"
                                </p>
                                <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                                    <div style={{
                                        width:36, height:36, borderRadius:"50%",
                                        background:C.accentMuted,
                                        border:`1px solid rgba(245,158,11,0.22)`,
                                        display:"flex", alignItems:"center", justifyContent:"center",
                                        fontSize:"0.72rem", fontWeight:700, color:C.accent, flexShrink:0
                                    }}>
                                        {t.initials}
                                    </div>
                                    <div>
                                        <p style={{ fontSize:"0.85rem", fontWeight:600, color:C.fg, marginBottom:2, fontFamily:"'Space Grotesk',sans-serif" }}>
                                            {t.name}
                                        </p>
                                        <p style={{ fontSize:"0.72rem", color:C.fgMuted, fontFamily:"'JetBrains Mono',monospace" }}>
                                            {t.role}
                                        </p>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── CTA ────────────────────────────────────────────── */}
            <section style={{ padding:"6rem 1.5rem", position:"relative", zIndex:1, overflow:"hidden" }}>
                {/* Accent glow behind CTA */}
                <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center", justifyContent:"center", pointerEvents:"none" }}>
                    <div style={{ width:500, height:200, background:C.accent, filter:"blur(100px)", opacity:0.06, borderRadius:"50%" }} />
                </div>
                <div style={{ maxWidth:580, margin:"0 auto", textAlign:"center", position:"relative" }}>
                    <div style={{
                        width:50, height:50, borderRadius:14, background:C.accentMuted,
                        border:`1px solid rgba(245,158,11,0.22)`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        margin:"0 auto 1.5rem"
                    }}>
                        <Shield size={22} strokeWidth={1.5} color={C.accent} />
                    </div>
                    <h2 style={{
                        fontFamily:"'Space Grotesk',sans-serif",
                        fontSize:"clamp(1.75rem,4vw,2.75rem)",
                        fontWeight:800, letterSpacing:"-0.04em",
                        color:C.fg, marginBottom:16, lineHeight:1.1
                    }}>
                        Ready to ship great work?
                    </h2>
                    <p style={{ fontSize:"1rem", color:C.fgMuted, lineHeight:1.7, marginBottom:36 }}>
                        Join thousands of teams who deliver faster with ProjectFlow. Free forever for small teams.
                    </p>
                    <div style={{ display:"flex", justifyContent:"center", gap:12, flexWrap:"wrap" }}>
                        <Link to="/register" style={btnPrimary}
                            onMouseEnter={e=>{e.currentTarget.style.filter="brightness(1.1)";e.currentTarget.style.boxShadow=`0 0 28px ${C.accentGlow}`}}
                            onMouseLeave={e=>{e.currentTarget.style.filter="none";e.currentTarget.style.boxShadow="none"}}
                        >
                            Create free account <ArrowRight size={15} />
                        </Link>
                        <Link to="/login" style={btnOutline}
                            onMouseEnter={e=>{e.currentTarget.style.background="rgba(255,255,255,0.05)"}}
                            onMouseLeave={e=>{e.currentTarget.style.background="transparent"}}
                        >
                            Sign in
                        </Link>
                    </div>
                </div>
            </section>

            {/* ── Footer ─────────────────────────────────────────── */}
            <footer style={{ borderTop:`1px solid ${C.border}`, background:C.bgAlt, padding:"3rem 1.5rem 2rem", position:"relative", zIndex:1 }}>
                <div style={{ maxWidth:1100, margin:"0 auto" }}>
                    <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr 1fr 1fr", gap:"2.5rem", marginBottom:"2.5rem" }} className="lp-footer-grid">
                        {/* Brand */}
                        <div>
                            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                                <div style={{ width:26, height:26, borderRadius:7, background:C.accent, display:"flex", alignItems:"center", justifyContent:"center" }}>
                                    <Zap size={13} color={C.accentFg} strokeWidth={2.5} />
                                </div>
                                <span style={{ fontFamily:"'Space Grotesk',sans-serif", fontWeight:700, fontSize:"0.9rem", color:C.fg }}>ProjectFlow</span>
                            </div>
                            <p style={{ fontSize:"0.8rem", color:C.fgMuted, lineHeight:1.7, maxWidth:200 }}>
                                The modern project management platform for teams that ship fast.
                            </p>
                        </div>

                        {/* Link columns */}
                        {[
                            { title:"Product", links:["Features","Pricing","Changelog","Roadmap"] },
                            { title:"Company", links:["About","Blog","Careers","Contact"]          },
                            { title:"Legal",   links:["Privacy","Terms","Security","Cookies"]      },
                        ].map(col => (
                            <div key={col.title}>
                                <p style={{ fontSize:"0.65rem", fontWeight:700, color:C.fgMuted, textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:14, fontFamily:"'JetBrains Mono',monospace" }}>
                                    {col.title}
                                </p>
                                <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                                    {col.links.map(l => (
                                        <a key={l} href="#" style={{ fontSize:"0.83rem", color:C.fgMuted, textDecoration:"none", transition:"color 200ms" }}
                                            onMouseEnter={e=>e.target.style.color=C.fg}
                                            onMouseLeave={e=>e.target.style.color=C.fgMuted}
                                        >{l}</a>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Bottom bar */}
                    <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:20, display:"flex", justifyContent:"space-between", alignItems:"center", flexWrap:"wrap", gap:10 }}>
                        <p style={{ fontSize:"0.75rem", color:C.fgSubtle, fontFamily:"'JetBrains Mono',monospace" }}>
                            © {new Date().getFullYear()} ProjectFlow. All rights reserved.
                        </p>
                        <p style={{ fontSize:"0.75rem", color:C.fgSubtle }}>
                            Built for teams that care about quality.
                        </p>
                    </div>
                </div>
            </footer>

            {/* ── Global styles ──────────────────────────────────── */}
            <style>{`
                @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&family=Inter:wght@400;450;500;600&family=JetBrains+Mono:wght@400;600&display=swap');
                *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
                body { -webkit-font-smoothing: antialiased; }

                @keyframes lp-pulse {
                    0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(245,158,11,0.5); }
                    50%       { opacity: 0.5; box-shadow: 0 0 3px rgba(245,158,11,0.2); }
                }

                .lp-desktop-nav { display: flex !important; }
                .lp-mobile-only  { display: none  !important; }

                @media (max-width: 768px) {
                    .lp-desktop-nav { display: none  !important; }
                    .lp-mobile-only  { display: flex !important; }
                    .lp-footer-grid  { grid-template-columns: 1fr 1fr !important; }
                }
                @media (max-width: 480px) {
                    .lp-footer-grid { grid-template-columns: 1fr !important; }
                }
            `}</style>
        </div>
    );
};

/* ── Reusable section header ───────────────────────────────────── */
const SectionHeader = ({ label, title, sub }) => (
    <div style={{ textAlign:"center", marginBottom:"3rem" }}>
        <span style={{
            display:"inline-block",
            fontFamily:"'JetBrains Mono',monospace",
            fontSize:"0.7rem", fontWeight:600, letterSpacing:"0.1em",
            textTransform:"uppercase", color:"#F59E0B",
            marginBottom:14
        }}>
            {label}
        </span>
        <h2 style={{
            fontFamily:"'Space Grotesk',sans-serif",
            fontSize:"clamp(1.6rem,4vw,2.5rem)",
            fontWeight:800, letterSpacing:"-0.04em",
            color:"#FAFAFA", marginBottom: sub ? 14 : 0, lineHeight:1.1
        }}>
            {title}
        </h2>
        {sub && <p style={{ fontSize:"0.9rem", color:"#71717A", maxWidth:400, margin:"0 auto", lineHeight:1.7 }}>{sub}</p>}
    </div>
);

export default LandingPage;