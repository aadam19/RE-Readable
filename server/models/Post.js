const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const PostSchema = new Schema({
    title: { type: String, required: true },
    author: { type: String, required: true },
    owner: { type: String, required: true },
    condition: { type: String, required: true },
    price: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now, immutable: true },
    img: { type: String, required: true }
}, { collection: 'books' });

module.exports = mongoose.model('Post', PostSchema);