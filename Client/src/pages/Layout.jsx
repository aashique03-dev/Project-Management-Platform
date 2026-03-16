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

    // ✅ Removed: if (loading) return <Loader2Icon />
    // That was unmounting the entire layout every time fetchProjects ran,
    // which unmounted Sidebar, which remounted it, which called fetchProjects
    // again — causing an infinite loop.

    return (
        <div className="flex bg-white dark:bg-zinc-950 text-gray-900 dark:text-slate-100">
            <Sidebar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />
            <div className="flex-1 flex flex-col h-screen">
                <Navbar isSidebarOpen={isSidebarOpen} setIsSidebarOpen={setIsSidebarOpen} />
                <div className="flex-1 h-full p-6 xl:p-10 xl:px-16 overflow-y-scroll">
                    <Outlet />
                </div>
            </div>
        </div>
    )
}

export default Layout