import express from "express"
import cors from "cors"
import healthCheckRouter from "./routes/healthchech.routes.js"
import authRoute from "./routes/auth.routes.js"


const app = express()


//Basic configuration
app.use(express.json({ limit: "16kb" }))
app.use(express.urlencoded({ extended: true, limit: "16kb" }))
app.use(express.static("public"))


// cors configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}))

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRoute);


app.get("/", (req, res) => {
    console.log("Hello world");
    res.json({ message: "Hello" })
})
export { app }