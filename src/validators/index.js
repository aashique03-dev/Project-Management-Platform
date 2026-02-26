import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid"),
        body("userName")
            .trim()
            .notEmpty()
            .withMessage("userName is required")
            .isLowercase()
            .withMessage("userName must be is lower case")
            .isLength({ min: 3 })
            .withMessage("userName must be at least 3 characters long"),
        body("password")
            .trim()
            .notEmpty()
            .withMessage("Password is required")
            .isLength({ min: 6 })
            .withMessage("Password must be at least 3 characters long"),
        body("fullName").optional()
            .trim()
    ]
}

export {
    userRegisterValidator
}