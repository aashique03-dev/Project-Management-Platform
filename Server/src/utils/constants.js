export const UserRolesEnum = {
    ADMIN: "admin",
    PROJECT_ADMIN: "project_admin",
    MEMBER: "member"
}
export const AvailableUserRole = Object.values(UserRolesEnum)

export const TaskStatusEnum = {
    TODO: "todo",
    IN_PROGRESS: "in_progress",
    DONE: "done"
}
export const AvailableTaskStatus = Object.values(TaskStatusEnum)

export const TaskTypeEnum = {
    TASK: "TASK",
    BUG: "BUG",
    FEATURE: "FEATURE",
    IMPROVEMENT: "IMPROVEMENT",
    OTHER: "OTHER",
}
export const AvailableTaskType = Object.values(TaskTypeEnum)

export const TaskPriorityEnum = {
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    HIGH: "HIGH",
}
export const AvailableTaskPriority = Object.values(TaskPriorityEnum)