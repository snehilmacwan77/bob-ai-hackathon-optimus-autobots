import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Search, FolderOpen, Shield, ShieldAlert, Activity } from 'lucide-react';

const nav = [
  { to: '/',           icon: LayoutDashboard, label: 'Dashboard'       },
  { to: '/analyze',    icon: Search,          label: 'Analyze IOC'     },
  { to: '/indicators', icon: Activity,        label: 'Indicators'      },
  { to: '/incidents',  icon: FolderOpen,      label: 'Incidents'       },
];

export default function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 w-56 bg-slate-900 border-r border-slate-800 flex flex-col z-30">
      <div className="flex items-center gap-2.5 px-4 py-5 border-b border-slate-800">
        <ShieldAlert className="w-6 h-6 text-blue-400 shrink-0" />
        <div>
          <p className="text-sm font-bold text-white leading-tight">ThreatFusion AI</p>
          <p className="text-[10px] text-slate-500 leading-tight">Threat Intelligence System</p>
        </div>
      </div>

      <nav className="flex-1 py-4 px-2 space-y-0.5">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400 font-medium'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
              }`
            }
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-slate-800 space-y-1">
        <div className="flex items-center gap-1.5">
          <Shield className="w-3 h-3 text-amber-400" />
          <p className="text-[10px] text-amber-400 font-medium">Demo / Synthetic Data Only</p>
        </div>
        <p className="text-[9px] text-slate-600">IBM Bob AI Hackathon · Team Optimus Autobots</p>
      </div>
    </aside>
  );
}
