import { ApiResponse } from "../utils/apiResponse.js"
import { asyncHandler } from "../utils/async-handler.js"

const healthCheck = asyncHandler(async (req, res) => {
    res.status(200).json(
        new ApiResponse(200, {
            message: "Server is running"
        })
    )
})

export { healthCheck }