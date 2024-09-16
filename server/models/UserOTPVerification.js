const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const UserOTPVerificationSchema = new Schema({
    userId: String,
    otp: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: Date.now, index: { expires: '5m' } }
});

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPVerificationSchema);
module.exports = UserOTPVerification;