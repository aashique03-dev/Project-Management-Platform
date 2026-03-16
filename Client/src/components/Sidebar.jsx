import { useEffect, useRef } from 'react'
import { NavLink } from 'react-router-dom'
import MyTasksSidebar from './MyTasksSidebar'
import ProjectSidebar from './ProjectsSidebar'
import { FolderOpenIcon, LayoutDashboardIcon, SettingsIcon, UsersIcon, LayoutGridIcon, Loader2Icon } from 'lucide-react'
import { useDispatch, useSelector } from 'react-redux'
import { fetchProjects } from '../features/workspaceSlice'

const Sidebar = ({ isSidebarOpen, setIsSidebarOpen }) => {

    const dispatch = useDispatch()
    const user = useSelector((state) => state.auth?.user)
    const loading = useSelector((state) => state.workspace.loading)

    const menuItems = [
        { name: 'Dashboard', href: '/', icon: LayoutDashboardIcon },
        { name: 'Projects', href: '/projects', icon: FolderOpenIcon },
        { name: 'Team', href: '/team', icon: UsersIcon },
    ]

    const sidebarRef = useRef(null)

    useEffect(() => {
        dispatch(fetchProjects())
    }, [dispatch])

    useEffect(() => {
        function handleClickOutside(event) {
            if (sidebarRef.current && !sidebarRef.current.contains(event.target)) {
                setIsSidebarOpen(false)
            }
        }
        document.addEventListener('mousedown', handleClickOutside)
        return () => document.removeEventListener('mousedown', handleClickOutside)
    }, [setIsSidebarOpen])

    return (
        <div
            ref={sidebarRef}
            className={`z-10 bg-white dark:bg-zinc-900 min-w-68 flex flex-col h-screen border-r border-gray-200 dark:border-zinc-800 max-sm:absolute transition-all ${isSidebarOpen ? 'left-0' : '-left-full'}`}
        >
            {/* Workspace Header */}
            <div className="flex items-center gap-3 m-4 p-3 rounded-lg bg-gray-50 dark:bg-zinc-800">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center flex-shrink-0">
                    <LayoutGridIcon className="w-4 h-4 text-white" />
                </div>
                <div className="min-w-0 flex-1">
                    <p className="font-semibold text-gray-800 dark:text-white text-sm truncate">
                        {user?.fullName || 'My Workspace'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-zinc-400 truncate">
                        {user?.email || 'Personal workspace'}
                    </p>
                </div>
            </div>

            <hr className="border-gray-200 dark:border-zinc-800" />

            <div className="flex-1 overflow-y-scroll no-scrollbar flex flex-col">
                <div>
                    <div className="p-4">
                        {menuItems.map((item) => (
                            <NavLink
                                to={item.href}
                                key={item.name}
                                className={({ isActive }) =>
                                    `flex items-center gap-3 py-2 px-4 text-gray-800 dark:text-zinc-100 cursor-pointer rounded transition-all ${isActive
                                        ? 'bg-gray-100 dark:bg-gradient-to-br dark:from-zinc-800 dark:to-zinc-800/50'
                                        : 'hover:bg-gray-50 dark:hover:bg-zinc-800/60'
                                    }`
                                }
                            >
                                <item.icon size={16} />
                                <p className="text-sm truncate">{item.name}</p>
                            </NavLink>
                        ))}
                        <button className="flex w-full items-center gap-3 py-2 px-4 text-gray-800 dark:text-zinc-100 cursor-pointer rounded hover:bg-gray-50 dark:hover:bg-zinc-800/60 transition-all">
                            <SettingsIcon size={16} />
                            <p className="text-sm truncate">Settings</p>
                        </button>
                    </div>

                    {/* ✅ Show spinner inline while loading, don't block the whole UI */}
                    {loading ? (
                        <div className="flex items-center justify-center py-8">
                            <Loader2Icon className="w-5 h-5 text-blue-500 animate-spin" />
                        </div>
                    ) : (
                        <>
                            <MyTasksSidebar />
                            <ProjectSidebar />
                        </>
                    )}
                </div>
            </div>
        </div>
    )
}

export default Sidebar