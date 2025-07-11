// src/App.jsx
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import ProjectDetails from "./pages/ProjectDetails";
import ScannedReports from "./pages/ScannedReports";
import SidebarLayout from "./layout/SidebarLayout";

function App() {
  return (
    <Router>
      <Routes>
        <Route element={<SidebarLayout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/projects/:id" element={<ProjectDetails />} />
          <Route path="/reports" element={<ScannedReports />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;