import mongoose, { Schema, Document } from "mongoose";

// Define the interface for a refresh token document
interface IRefreshToken extends Document {
    userId: string;
    token: string;
    expiresAt: Date;
}

const RefreshTokenSchema: Schema = new Schema({
    userId: {
        type: String,
        required: true,
    },
    token: {
        type: String,
        required: true,
    },
    expiresAt: {
        type: Date,
        required: true,
    },
});

const RefreshToken = mongoose.model<IRefreshToken>(
    "RefreshToken",
    RefreshTokenSchema,
);

export default RefreshToken;
