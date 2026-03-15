import { Router } from "express";
import {
  createTask,
  getTasks,
  getTaskById,
  updateTask,
  deleteTask,
  createSubTask,
  updateSubTask,
  deleteSubTask,
} from "../controllers/task.controllers.js";
import { verifyJwt } from "../middlewares/auth.middlewares.js";
import { upload } from "../middlewares/multer.middlewares.js";

const router = Router();
router.use(verifyJwt);

router
  .route("/project/:projectId")
  .get(getTasks)
  .post(upload.array("attachments"), createTask);

router
  .route("/:taskId")
  .get(getTaskById)
  .patch(updateTask)
  .delete(deleteTask);

router
  .route("/:taskId/subtasks")
  .post(createSubTask);

router
  .route("/subtasks/:subtaskId")
  .patch(updateSubTask)
  .delete(deleteSubTask);

export default router;
