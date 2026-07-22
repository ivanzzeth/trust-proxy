import '~/styles/main.scss';
import './misc/i18n';

import React from 'react';
import { createRoot } from 'react-dom/client';
import Modal from 'react-modal';

import App from './App';
import { registerAppBootstrap } from './app/bootstrap';
import * as swRegistration from './swRegistration';

const rootEl = document.getElementById('app');
if (!rootEl) {
	throw new Error('Cannot find #app root element');
}

const root = createRoot(rootEl);

Modal.setAppElement(rootEl);

root.render(<App />);

swRegistration.register();

registerAppBootstrap(rootEl);
