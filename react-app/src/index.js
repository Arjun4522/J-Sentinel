import React from 'react';
import ReactDOM from 'react-dom/client';  // correct import for React 18
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { ThemeProvider, createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    primary: { main: '#1976d2' },
    secondary: { main: '#dc004e' },
  },
});

// ✅ Create the root first
const container = document.getElementById('root');
const root = ReactDOM.createRoot(container);

// ✅ Then call render on the root
root.render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <App />
    </ThemeProvider>
  </React.StrictMode>
);

reportWebVitals();
