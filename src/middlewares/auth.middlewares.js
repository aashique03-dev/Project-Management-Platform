import { User } from "../models/user.models.js"
import { ApiError } from "../utils/apiError.js"
import { asyncHandler } from "../utils/async-handler.js"
import jwt from "jsonwebtoken"



export const verifyJwt = asyncHandler(async (req, res, next) => {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearar ", "")

    if (!token) {
        throw new ApiError(401, "Unauthorization request")
    }

    try {
        const deccodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        const user = await User.findById(deccodedToken?._id).select(
            "-password- -refreshToken- -emailVerificationToken- -emailVerificationExpiry- "
        );

        if (!user) {
            throw new ApiError(401, "invalid access token")
        }

        req.user = user
        next()

    } catch (error) {
        throw new ApiError(401, "invalid access token")

    }


})