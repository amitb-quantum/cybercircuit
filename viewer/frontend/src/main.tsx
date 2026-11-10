import { createRoot } from 'react-dom/client';
import { adapter } from '@adapter';
import { App } from './App';
import './styles/console.css';
import './styles/design.css';

createRoot(document.getElementById('root')!).render(<App adapter={adapter} />);
