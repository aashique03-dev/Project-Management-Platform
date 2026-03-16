import { Link } from "react-router-dom";
import { CheckCircleIcon, LayoutDashboardIcon, UsersIcon, CalendarIcon, BarChart2Icon } from "lucide-react";

const features = [
    { icon: LayoutDashboardIcon, title: "Project Dashboard", desc: "Get a bird's-eye view of all your projects and their progress in one place." },
    { icon: UsersIcon, title: "Team Collaboration", desc: "Invite members, assign roles, and work together seamlessly." },
    { icon: CheckCircleIcon, title: "Task Management", desc: "Create, assign, and track tasks with priorities and deadlines." },
    { icon: BarChart2Icon, title: "Analytics", desc: "Visualize project progress and team performance with clear charts." },
    { icon: CalendarIcon, title: "Calendar View", desc: "See all your deadlines and milestones in a clean calendar layout." },
];

const LandingPage = () => {
    return (
        <div className="min-h-screen bg-gray-50 flex flex-col">

            {/* Navbar */}
            <nav className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center">
                        <LayoutDashboardIcon className="w-4 h-4 text-white" />
                    </div>
                    <span className="font-bold text-gray-800 text-lg">ProjectManager</span>
                </div>
                <div className="flex items-center gap-3">
                    <Link
                        to="/login"
                        className="text-sm font-medium text-gray-600 hover:text-gray-900 px-4 py-2 rounded-md hover:bg-gray-100 transition"
                    >
                        Sign in
                    </Link>
                    <Link
                        to="/register"
                        className="text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-md transition"
                    >
                        Get started
                    </Link>
                </div>
            </nav>

            {/* Hero */}
            <section className="flex-1 flex flex-col items-center justify-center text-center px-6 py-24">
                <span className="text-xs font-semibold text-blue-600 bg-blue-50 border border-blue-200 px-3 py-1 rounded-full mb-6 uppercase tracking-wider">
                    Project Management Platform
                </span>
                <h1 className="text-4xl sm:text-5xl font-bold text-gray-900 max-w-2xl leading-tight mb-6">
                    Manage projects and teams{" "}
                    <span className="text-blue-600">without the chaos</span>
                </h1>
                <p className="text-gray-500 text-lg max-w-xl mb-10">
                    Plan, track, and deliver your projects on time. Collaborate with your team, manage tasks, and stay on top of deadlines — all in one place.
                </p>
                <div className="flex items-center gap-4 flex-wrap justify-center">
                    <Link
                        to="/register"
                        className="px-6 py-3 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition shadow"
                    >
                        Start for free
                    </Link>
                    <Link
                        to="/login"
                        className="px-6 py-3 text-sm font-semibold text-gray-700 bg-white hover:bg-gray-100 border border-gray-300 rounded-lg transition"
                    >
                        Sign in to your account
                    </Link>
                </div>
            </section>

            {/* Features */}
            <section className="bg-white border-t border-gray-200 px-6 py-20">
                <div className="max-w-5xl mx-auto">
                    <h2 className="text-2xl font-bold text-gray-900 text-center mb-12">
                        Everything your team needs
                    </h2>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
                        {features.map((feature) => (
                            <div key={feature.title} className="flex gap-4">
                                <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center flex-shrink-0">
                                    <feature.icon className="w-5 h-5 text-blue-600" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-gray-800 mb-1">{feature.title}</h3>
                                    <p className="text-sm text-gray-500">{feature.desc}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="border-t border-gray-200 px-6 py-6 text-center text-sm text-gray-400">
                © {new Date().getFullYear()} ProjectManager. All rights reserved.
            </footer>
        </div>
    );
};

export default LandingPage;