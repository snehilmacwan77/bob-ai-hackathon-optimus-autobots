import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import Indicators from './pages/Indicators';
import { IncidentList, IncidentDetail } from './pages/Incidents';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-slate-950">
        <Sidebar />
        <main className="flex-1 ml-56 p-6 overflow-auto">
          <div className="max-w-6xl mx-auto">
            <Routes>
              <Route path="/"                element={<Dashboard />}      />
              <Route path="/analyze"         element={<Analyze />}        />
              <Route path="/indicators"      element={<Indicators />}     />
              <Route path="/incidents"       element={<IncidentList />}   />
              <Route path="/incidents/:id"   element={<IncidentDetail />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}
