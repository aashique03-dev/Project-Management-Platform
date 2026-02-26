import { Router } from "express"
import { login, logoutUser, registerUser } from "../controllers/auth.controllers.js"
import { validate } from "../middlewares/validators.middlewares.js"
import { userRegisterValidator, userLogginValidator } from "../validators/index.js"
import { verifyJwt } from "../middlewares/auth.middlewares.js"


const router = Router()

router.route("/register").post(userRegisterValidator(), validate, registerUser)
router.route("/login").post(userLogginValidator(), validate, login)
router.route("/logout").post(verifyJwt, logoutUser)


export default router