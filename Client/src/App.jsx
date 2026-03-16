import { Routes, Route, Navigate, Outlet } from "react-router-dom";
import { useSelector } from "react-redux";
import Layout from "./pages/Layout";
import { Toaster } from "react-hot-toast";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import Team from "./pages/Team";
import ProjectDetails from "./pages/ProjectDetails";
import TaskDetails from "./pages/TaskDetails";
import Login from "./pages/login";
import Register from "./pages/Register";
import LandingPage from "./pages/LandingPage";

// Redirects logged-in users away from public pages (landing, login, register)
const PublicRoute = () => {
    const isAuthenticated = useSelector((state) => state.auth.isAuthenticated);
    return isAuthenticated ? <Navigate to="/" replace /> : <Outlet />;
};

// Redirects logged-out users away from protected pages
const ProtectedRoute = () => {
    const isAuthenticated = useSelector((state) => state.auth.isAuthenticated);
    return isAuthenticated ? <Outlet /> : <Navigate to="/landing" replace />;
};

const App = () => {
    return (
        <>
            <Toaster position="top-right" />
            <Routes>
                {/* Public routes — redirect to dashboard if already logged in */}
                <Route element={<PublicRoute />}>
                    <Route path="/landing" element={<LandingPage />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                </Route>

                {/* Protected routes — redirect to landing if not logged in */}
                <Route element={<ProtectedRoute />}>
                    <Route path="/" element={<Layout />}>
                        <Route index element={<Dashboard />} />
                        <Route path="team" element={<Team />} />
                        <Route path="projects" element={<Projects />} />
                        <Route path="projectsDetail" element={<ProjectDetails />} />
                        <Route path="taskDetails" element={<TaskDetails />} />
                    </Route>
                </Route>

                {/* Catch-all redirect */}
                <Route path="*" element={<Navigate to="/landing" replace />} />
            </Routes>
        </>
    );
};

export default App;