// Helper to check if a file's size is within the allowed range for AI analysis
const fs = require('fs');

/**
 * Checks if the file size is suitable for AI analysis (between 1KB and 25MB).
 * Returns true if the file size is within the allowed range, false otherwise.
 * @param {string} filePath - Path to the file to check
 * @returns {boolean} - True if file size is suitable, false otherwise
 */
function isFileSizeSuitable(filePath) {
  try {
    const stats = fs.statSync(filePath);
    const sizeInBytes = stats.size;
    const minSize = 1024; // 1KB
    const maxSize = 25 * 1024 * 1024; // 25MB
    return sizeInBytes >= minSize && sizeInBytes <= maxSize;
  } catch (error) {
    console.error('Error checking file size:', error);
    return false;
  }
}

module.exports = isFileSizeSuitable; 