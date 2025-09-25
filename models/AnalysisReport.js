const mongoose = require('mongoose');

const analysisReportSchema = new mongoose.Schema({
  fileId: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true },
  analysisDate: { type: Date, required: true },
  predictions_file: { type: String, required: true }, // 'Malicious' or 'Benign'
  probability_file: { type: Number, default: null },
  predictions_family: { type: [String], default: [] },
  probability_family: { type: [Number], default: [] }
});

module.exports = mongoose.model('AnalysisReport', analysisReportSchema); 

//console.log('AI Model Response:', aiResult); 