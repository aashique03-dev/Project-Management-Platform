import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../api/axios";

// ─── Async Thunks ────────────────────────────────────────────────────────────

export const fetchProjects = createAsyncThunk(
  "workspace/fetchProjects",
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get("/projects");
      return response.data;
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to fetch projects"
      );
    }
  }
);

export const createProject = createAsyncThunk(
  "workspace/createProject",
  async (projectData, { rejectWithValue }) => {
    try {
      const response = await api.post("/projects", projectData);
      return response.data;
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to create project"
      );
    }
  }
);

export const fetchProjectTasks = createAsyncThunk(
  "workspace/fetchProjectTasks",
  async (projectId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/tasks/project/${projectId}`);
      return { projectId, tasks: response.data.data };
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to fetch tasks"
      );
    }
  }
);

export const createTask = createAsyncThunk(
  "workspace/createTask",
  async (taskData, { rejectWithValue }) => {
    try {
      const response = await api.post(
        `/tasks/project/${taskData.projectId}`,
        taskData
      );
      return { projectId: taskData.projectId, task: response.data.data };
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to create task"
      );
    }
  }
);

export const updateTask = createAsyncThunk(
  "workspace/updateTask",
  async (taskData, { rejectWithValue }) => {
    try {
      const response = await api.patch(`/tasks/${taskData._id || taskData.id}`, taskData);
      return { projectId: taskData.projectId, task: response.data.data };
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to update task"
      );
    }
  }
);

export const deleteTask = createAsyncThunk(
  "workspace/deleteTask",
  async ({ taskId, projectId }, { rejectWithValue }) => {
    try {
      await api.delete(`/tasks/${taskId}`);
      return { taskId, projectId };
    } catch (err) {
      return rejectWithValue(
        err.response?.data?.message || "Failed to delete task"
      );
    }
  }
);

// ─── Slice ───────────────────────────────────────────────────────────────────

const initialState = {
  currentWorkspace: {
    id: "default_workspace",
    name: "My Workspace",
    projects: [],
    members: [],
  },
  loading: false,
  error: null,
};

const workspaceSlice = createSlice({
  name: "workspace",
  initialState,
  reducers: {
    resetWorkspace: (state) => {
      state.currentWorkspace = {
        id: "default_workspace",
        name: "My Workspace",
        projects: [],
        members: [],
      };
      state.loading = false;
      state.error = null;
    }
  }, extraReducers: (builder) => {
    builder
      // ─── Fetch Projects ───────────────────────────────────────────
      .addCase(fetchProjects.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchProjects.fulfilled, (state, action) => {
        state.loading = false;

        // API returns: { data: [ { project: {...}, role: "..." }, ... ] }
        // We extract the nested project objects and attach the role to each
        const raw = Array.isArray(action.payload.data)
          ? action.payload.data
          : Array.isArray(action.payload)
            ? action.payload
            : [];

        state.currentWorkspace.projects = raw.map((item) => {
          // If the item has a "project" key (aggregation shape), unwrap it
          const p = item.project ?? item;
          return {
            ...p,
            role: item.role ?? null,
            tasks: p.tasks || [],
          };
        });
      })
      .addCase(fetchProjects.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })

      // ─── Create Project ───────────────────────────────────────────
      .addCase(createProject.fulfilled, (state, action) => {
        const newProject = action.payload.data || action.payload;
        state.currentWorkspace.projects.push({ ...newProject, tasks: [] });
      })

      // ─── Fetch Project Tasks ──────────────────────────────────────
      .addCase(fetchProjectTasks.fulfilled, (state, action) => {
        const { projectId, tasks } = action.payload;
        const project = state.currentWorkspace.projects.find(
          (p) => p._id === projectId || p.id === projectId
        );
        if (project) project.tasks = tasks;
      })

      // ─── Create Task ──────────────────────────────────────────────
      .addCase(createTask.fulfilled, (state, action) => {
        const { projectId, task } = action.payload;
        const project = state.currentWorkspace.projects.find(
          (p) => p._id === projectId || p.id === projectId
        );
        if (project) project.tasks.push(task);
      })

      // ─── Update Task ──────────────────────────────────────────────
      .addCase(updateTask.fulfilled, (state, action) => {
        const { projectId, task } = action.payload;
        const project = state.currentWorkspace.projects.find(
          (p) => p._id === projectId || p.id === projectId
        );
        if (project) {
          const index = project.tasks.findIndex(
            (t) => t._id === task._id || t.id === task.id
          );
          if (index !== -1) project.tasks[index] = task;
        }
      })

      // ─── Delete Task ──────────────────────────────────────────────
      .addCase(deleteTask.fulfilled, (state, action) => {
        const { taskId, projectId } = action.payload;
        const project = state.currentWorkspace.projects.find(
          (p) => p._id === projectId || p.id === projectId
        );
        if (project) {
          project.tasks = project.tasks.filter(
            (t) => t._id !== taskId && t.id !== taskId
          );
        }
      });
  },
});

export const { resetWorkspace } = workspaceSlice.actions;
export default workspaceSlice.reducer;