const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  name: { type: String, required: true },
  hash: { type: String, unique: true, required: true },
  status: { type: String, enum: ['pending', 'analyzed'], default: 'pending' },
  uploadDate: { type: Date, default: Date.now },
  // userId is optional; 0 means guest upload
  userId: { type: mongoose.Schema.Types.Mixed, default: 0 }
});

module.exports = mongoose.model('File', fileSchema); 