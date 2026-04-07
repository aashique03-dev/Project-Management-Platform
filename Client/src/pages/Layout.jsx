import { useState, useEffect } from 'react'
import Navbar from '../components/Navbar'
import Sidebar from '../components/Sidebar'
import { Outlet } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import { loadTheme } from '../features/themeSlice'

const Layout = () => {
    const [isSidebarOpen, setIsSidebarOpen] = useState(false)
    const dispatch = useDispatch()

    useEffect(() => {
        dispatch(loadTheme())
    }, [])

    return (
        <div style={{
            display: "flex",
            background: "var(--bg)",
            color: "var(--fg)",
            minHeight: "100vh"
        }}>
            {/* Ambient background orbs */}
            <div className="ambient-bg">
                <div className="ambient-orb ambient-orb-1" />
                <div className="ambient-orb ambient-orb-2" />
            </div>

            <Sidebar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />

            <div style={{
                flex: 1,
                display: "flex",
                flexDirection: "column",
                height: "100vh",
                overflow: "hidden",
                position: "relative",
                zIndex: 1
            }}>
                <Navbar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />
                <div style={{
                    flex: 1,
                    overflowY: "auto",
                    padding: "1.75rem 1.5rem",
                }}>
                    <div style={{ maxWidth: "80rem", margin: "0 auto" }}>
                        <Outlet />
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Layout