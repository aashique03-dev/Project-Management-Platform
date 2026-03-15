import { Router } from "express";
import {
  createComment,
  getTaskComments,
  deleteComment,
} from "../controllers/comment.controllers.js";
import { verifyJwt } from "../middlewares/auth.middlewares.js";

const router = Router();
router.use(verifyJwt);

router
  .route("/task/:taskId")
  .get(getTaskComments)
  .post(createComment);

router
  .route("/:commentId")
  .delete(deleteComment);

export default router;
