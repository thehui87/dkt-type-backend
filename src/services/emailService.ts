// import nodemailer from "nodemailer";
const nodemailer = require("nodemailer");

export const resetPasswordTemplate = async (
    email: string,
    resetToken: string,
) => {
    const transporter = nodemailer.createTransport({
        host: "smtp.hostinger.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const resetUrl = `${process.env.FRONTEND_URI}/reset-password/${resetToken}`;

    const mailOptions = {
        from: "info@dwarfknight.com",
        to: email,
        subject: "Password Reset",
        text: `You are receiving this because you (or someone else) have requested the reset of your password. 
         Please click on the following link, or paste this into your browser to complete the process: 
         ${resetUrl}`,
    };

    await transporter.sendMail(mailOptions);
};
