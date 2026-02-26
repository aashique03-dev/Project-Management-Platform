import { User } from "../models/user.models.js"
import { ApiError } from "../utils/apiError.js"
import { ApiResponse } from "../utils/apiResponse.js"
import { asyncHandler } from "../utils/async-handler.js"
import { emailVerficationMailgenContent, sendEmail } from "../utils/mail.js"
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
export { registerUser, login }

