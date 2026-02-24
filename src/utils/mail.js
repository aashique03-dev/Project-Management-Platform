import Mailgen from "mailgen";
import nodemailer from "nodemailer"

const sendEmail = async (Option) => {
    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name: "Task Manager",
            link: "https://taskmanaglin.com"
        }
    })
    const emailTextual = mailGenerator.generatePlaintext(Option.mailgenContent)
    const emailhtml = mailGenerator.generate(Option.mailgenContent)

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS
        }
    })

    const mail = {
        from: "mi4281864@gmail.com",
        to: Option.email,
        subject: Option.subject,
        text: emailTextual,
        html: emailhtml
    }
    try {
        await transporter.sendMail(mail)
    } catch (error) {
        console.error("Email service failed silinetly. Make sure that MAILTRAP credentials in the .env file ");
        console.error("Error ",error);
        
    }
}

const emailVerficationMailgenContent =
    (username, verficationUrl) => {
        return {
            body: {
                name: username,
                intro: "Welcome to our App! We're very excited to have you on board.",
                action: {
                    instructions: "To Verify your email please click following button:",
                    button: {
                        color: "#2222bc",
                        text: "verify your eamil",
                        link: verficationUrl
                    },
                },
                outro: "Need help, or have question? Just reply to this email, We'd love to help"
            }
        }
    }



const forgotPAsswordMailgenContent =
    (username, passwordRestUrl) => {
        return {
            body: {
                name: username,
                intro: "we got a request to reset the password of your account",
                action: {
                    instructions: "To reset your password please click following button:",
                    button: {
                        color: "#2222bc",
                        text: "Reset password",
                        link: passwordRestUrl
                    },
                },
                outro: "Need help, or have question? Just reply to this email, We'd love to help"
            }
        }
    }



export {
    emailVerficationMailgenContent,
    forgotPAsswordMailgenContent,
    sendEmail
}

