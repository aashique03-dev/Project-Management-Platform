import mongoose, { Schema } from "mongoose";
import {
    AvailableTaskStatus,
    TaskStatusEnum,
    AvailableTaskType,
    TaskTypeEnum,
    AvailableTaskPriority,
    TaskPriorityEnum,
} from "../utils/constants.js";

const taskSchema = new Schema(
    {
        title: {
            type: String,
            required: true,
            trim: true,
        },
        description: String,
        project: {
            type: Schema.Types.ObjectId,
            ref: "Project",
            required: true,
        },
        assignedTo: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        assignedBy: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        status: {
            type: String,
            enum: AvailableTaskStatus,
            default: TaskStatusEnum.TODO,
        },
        // ✅ new field
        type: {
            type: String,
            enum: AvailableTaskType,
            default: TaskTypeEnum.TASK,
        },
        // ✅ new field
        priority: {
            type: String,
            enum: AvailableTaskPriority,
            default: TaskPriorityEnum.MEDIUM,
        },
        dueDate: {
            type: Date,
        },
        attachments: {
            type: [
                {
                    url: String,
                    mimetype: String,
                    size: Number,
                },
            ],
            default: [],
        },
    },
    { timestamps: true },
);

export const Task = mongoose.model("Task", taskSchema);