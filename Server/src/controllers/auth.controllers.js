import { User } from "../models/user.models.js"
import { ApiError } from "../utils/apiError.js"
import { ApiResponse } from "../utils/apiResponse.js"
import { asyncHandler } from "../utils/async-handler.js"
import { emailVerficationMailgenContent, sendEmail } from "../utils/mail.js"
import jwt, { decode } from "jsonwebtoken"

const generateAccessAndRefreshToken = async (userID) => {
    try {
        const user = await User.findById(userID)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })
        return { accessToken, refreshToken }
    } catch (error) {
        console.error(error)

        throw new ApiError(500, "somethin went wrong while generating access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { email, username, password, role } = req.body

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (existedUser) {
        throw new ApiError(409, "User with email or username is already exists", [])
    }
    const user = await User.create({
        email,
        password,
        username,
        isEmailVerified: true
    })

    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken()

    user.emailVerificationToken = hashedToken
    user.emailVerificationExpiry = tokenExpiry

    await user.save({ validateBeforeSave: false })

    await sendEmail({
        email: user?.email,
        subject: "Please verify your email",
        mailgenContent: emailVerficationMailgenContent(
            user.username,
            `${req.protocol}//${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        ),
    });
    const createdUser = await User.findById(user._id).select(
        "-password- -refreshToken- -emailVerificationToken- -emailVerificationExpiry- "
    )
    if (!createdUser) {
        throw new ApiError(500, "something went wrong while creating user")
    }

    return res.status(201).json(
        new ApiResponse(200, { user: createdUser },
            `User registered successfully and
              verification email has benn sent on you email`)
    )
})


const login = asyncHandler(async (req, res) => {
    const { email, password } = req.body

    if (!email) {
        throw new ApiError(400, "email is required")
    }
    const user = await User.findOne({ email })

    if (!user) {
        throw new ApiError(404, "user does not exists")
    }
    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(400, "invalid credentials")
    }
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)
    const loggedInUser = await User.findById(user._id).select(
        "-password- -refreshToken- -emailVerificationToken- -emailVerificationExpiry- "
    );

    const option = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, option)
        .cookie("refreshToken", refreshToken, option)
        .json(
            new ApiResponse(200, {
                user: loggedInUser,
                accessToken,
                refreshToken
            },
                "User logged in successfully"
            )
        )

})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req._id, {
        $set: {
            refreshToken: ""
        }
    },
        {
            new: true,
        }
    )
    const option = {
        httpOnly: true,
        secure: true
    }
    return res.status(200).clearCookie("accessToken", option).clearCookie("refreshToken", option).json(
        new ApiResponse(200, {}, "User logged out"))

})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, req.user, "Current user fetched successfully")
    )
})

const verifyEmail = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params

    if (!verificationToken) {
        throw new ApiError(400, "Email verification Token is missing")
    }
    let hashedToken = crypto.createHash("sha256").update(verificationToken).digest("hex")

    const user = await User.findOne({
        EmailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: Date.now() }
    })
    if (!user) {
        throw new ApiError(400, "Token is invalid or expired")
    }

    user.emailVerificationToken = undefined
    user.emailVerificationExpiry = undefined
    user.isEmailVerified = true
    await user.save({ validateBeforeSave: flase })

    return res.status(200).json(
        new ApiResponse(200,
            { isEmailVerified: true }, "Email is verified"
        )
    )
})
const resendEmailVerification = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)
    if (!user) {
        throw new ApiError(404, "User does not exit")
    }
    if (user.isEmailVerified) {
        throw new ApiError(409, "Eamil is already verified already")
    }
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken()

    user.emailVerificationToken = hashedToken
    user.emailVerificationExpiry = tokenExpiry

    await user.save({ validateBeforeSave: false })

    await sendEmail({
        email: user?.email,
        subject: "Please verify your email",
        mailgenContent: emailVerficationMailgenContent(
            user.username,
            `${req.protocol}//${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        ),
    });
    return res.status(200).json(
        new ApiResponse(200, {}, "Mail has been sent to you email ID")
    )
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized access")
    }
    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "invalid refresh token")
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired")
        }
        const option = {
            httpOnly: true,
            secure: true
        }
        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshToken(user._id)

        user.refreshToken = newRefreshToken;
        await user.save()
        return res.status(200).cookie("accessToken", accessToken, option).cookie("refreshToken", newRefreshToken, option)
            .json(new ApiResponse(
                200, { accessToken, refreshToken: newRefreshToken },
                "Access token refreshed"
            ))


    } catch (error) {
        throw new ApiError(401, "invalid refresh token")

    }

})

const forgotPasswordRequest = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(404, "User does not exists", []);
    }

    const { unHashedToken, hashedToken, tokenExpiry } =
        user.generateTemporaryToken();

    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

    await sendEmail({
        email: user?.email,
        subject: "Password reset request",
        mailgenContent: forgotPasswordMailgenContent(
            user.username,
            `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
        ),
    });

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Password reset mail has been sent on your mail id",
            ),
        );
});
const resetForgotPassword = asyncHandler(async (req, res) => {
    const { resetToken } = req.params;
    const { newPassword } = req.body;

    let hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    const user = await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: { $gt: Date.now() },
    });

    if (!user) {
        throw new ApiError(489, "Token is invalid or expired");
    }

    user.forgotPasswordExpiry = undefined;
    user.forgotPasswordToken = undefined;

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password reset successfully"));
});
const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);

    const isPasswordValid = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordValid) {
        throw new ApiError(400, "Invalid old Password");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"));
});

export {
    registerUser,
    login,
    logoutUser,
    getCurrentUser,
    verifyEmail,
    resendEmailVerification,
    refreshAccessToken,
    forgotPasswordRequest,
    resetForgotPassword,
    changeCurrentPassword
}

