import mongoose from "mongoose";
import jwt from "jsonwebtoken";

import { User } from "../models/user.models.js";
import { ProjectMember } from "../models/projectMember.model.js";

import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/async-handler.js";



export const verifyJwt = asyncHandler(async (req, res, next) => {
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")

    // if no token
    if (!token) {
        throw new ApiError(401, "Unauthorized request")
    }

    try {
        // verify token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

        // check payload
        if (!decodedToken?._id) {
            throw new ApiError(401, "Invalid token payload")
        }

        // get user
        const user = await User.findById(decodedToken._id).select(
            "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
        );

        // if user not found
        if (!user) {
            throw new ApiError(401, "Invalid access token")
        }

        // attach user to req
        req.user = user
        next()

    } catch (error) {
        throw new ApiError(401, "Invalid access token")
    }
})



export const validateProjectPermission = (roles = []) =>
  asyncHandler(async (req, res, next) => {
    const { projectId } = req.params;

    // check project id
    if (!projectId) {
      throw new ApiError(400, "Project ID is missing");
    }

    // find project membership
    const projectMember = await ProjectMember.findOne({
      project: new mongoose.Types.ObjectId(projectId),
      user: new mongoose.Types.ObjectId(req.user._id),
    });

    // if not member
    if (!projectMember) {
      throw new ApiError(404, "Project not found or access denied");
    }

    const givenRole = projectMember.role;

    // attach role
    req.projectRole = givenRole;

    // check role permission
    if (roles.length && !roles.includes(givenRole)) {
      throw new ApiError(
        403,
        "You do not have permission to perform this action"
      );
    }

    next();
  });