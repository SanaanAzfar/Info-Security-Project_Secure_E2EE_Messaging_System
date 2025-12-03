const nodemailer = require('nodemailer');
require('dotenv').config();

const hasEmailCredentials = process.env.EMAIL_USER && process.env.EMAIL_PASS;

let transporter;
if (hasEmailCredentials) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
}

const sendOTPEmail = async (email, otp) => {
  if (!hasEmailCredentials) {
    console.log(`Mock OTP for ${email} is ${otp}`);
    return;
  }

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for 2FA Verification',
    text: `Your OTP is: ${otp}. It will expire in 10 minutes.`,
    html: `<p>Your OTP is: <strong>${otp}</strong></p><p>It will expire in 10 minutes.</p>`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('OTP email sent successfully');
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
};

module.exports = { sendOTPEmail };