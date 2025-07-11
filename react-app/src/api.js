// src/api.js
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8080", // Update to your backend URL
});

export default api;
