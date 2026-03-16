// // new just for test
// import mongoose from "mongoose";

// const connectDB = async () => {
//   try {
//     const conn = await mongoose.connect(process.env.MONGODB_URI);
//     console.log(`✅ MongoDB connected ${conn.connection.host}`);
//   } catch (error) {
//     console.error("MongoDB connection error:", error);
//     process.exit(1);
//   }
// };

// export default connectDB;




//old one orginal
import mongoose from "mongoose";

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.DB_URL);
        console.log("✅ MongoDB connected");
    } catch (error) {
        console.error("❌ MongoDB connection error", error);
        process.exit(1)
    }
}

export default connectDB 
