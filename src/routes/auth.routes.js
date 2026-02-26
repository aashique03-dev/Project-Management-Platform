import { Router } from "express"
import { login, registerUser } from "../controllers/auth.controllers.js"
import { validate } from "../middlewares/validators.middlewares.js"
import { userRegisterValidator, userLogginValidator } from "../validators/index.js"


const router = Router()

router.route("/register").post(userRegisterValidator(), validate, registerUser)
router.route("/login").post(userLogginValidator(), validate, login)


export default router