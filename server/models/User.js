const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const UserSchema = new Schema({
    email: { type: String, required: true, undefined: true },
    username: { type: String, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    verified: { type: Boolean, default: false },
    image: { type: String },
    favourites: {
        type: [String], 
        default: []
      }
}, { collection: 'users' });

module.exports = mongoose.model('User', UserSchema);