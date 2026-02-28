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


export const validateProjectPermission = (roles = []) => {
  asyncHandler(async (req, res, next) => {
    const { projectId } = req.params;

    if (!projectId) {
      throw new ApiError(400, "project id is missing");
    }

    const project = await ProjectMember.findOne({
      project: new mongoose.Types.ObjectId(projectId),
      user: new mongoose.Types.ObjectId(req.user._id),
    });

    if (!project) {
      throw new ApiError(400, "project not found");
    }

    const givenRole = project?.role;

    req.user.role = givenRole;

    if (!roles.includes(givenRole)) {
      throw new ApiError(
        403,
        "You do not have permission to perform this action",
      );
    }

    next();
  });
};
