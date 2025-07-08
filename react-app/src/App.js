import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard/Dashboard';
import Layout from './components/Layout/Layout';

const App = () => {
  const [authenticated, setAuthenticated] = useState(!!localStorage.getItem('auth'));

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login setAuthenticated={setAuthenticated} />} />
        <Route
          path="/dashboard"
          element={
            authenticated ? (
              <Layout>
                <Dashboard />
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route
          path="*"
          element={<Navigate to={authenticated ? '/dashboard' : '/login'} />}
        />
      </Routes>
    </Router>
  );
};

export default App;
