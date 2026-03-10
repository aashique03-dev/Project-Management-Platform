import dotenv from "dotenv"
import { app } from "./app.js"
import connectDB from "./db/index.js"

dotenv.config({
    path: "./.env"
})
const PORT = process.env.PORT || 3000

connectDB()
    .then(()=>{
         app.listen(PORT, () => {
            console.log(`server is runing from http://localhost${PORT}`);
        })
    })
    .catch((err) => {
        console.error("MongoDB connection error", err);

    })