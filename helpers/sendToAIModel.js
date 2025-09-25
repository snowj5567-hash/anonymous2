// Helper to send a file to the external AI model for analysis
const fs = require('fs');
const axios = require('axios');

/**
 * Sends a file to the configured AI model endpoint for analysis.
 * Reads the file, encodes it as base64, and posts it to the AI model API.
 * Returns the AI model's response data.
 * Throws an error if the request fails.
 * @param {string} filePath - Path to the file to analyze
 * @param {string} [AI_MODEL_URL] - Optional override for the AI model URL
 * @param {object} [AI_MODEL_HEADERS] - Optional override for the AI model headers
 * @returns {Promise<object>} - The AI model's response data
 */
async function sendToAIModel(filePath, AI_MODEL_URL, AI_MODEL_HEADERS) {
  try {
    const fileContent = fs.readFileSync(filePath);
    const base64Content = fileContent.toString('base64');
    const payload = { file_bytes: base64Content };
    const url = AI_MODEL_URL || process.env.AI_MODEL_URL;
    const headers = AI_MODEL_HEADERS || { "Authorization": `Bearer ${process.env.AI_MODEL_TOKEN}` };
    const response = await axios.post(url, payload, {
      headers,
      timeout: 120000 // 2 minutes
    });
    return response.data;
  } catch (error) {
    console.error('AI Model Error:', error.response?.data || error.message);
    throw new Error(`AI Model request failed: ${error.message}`);
  }
}

module.exports = sendToAIModel; 