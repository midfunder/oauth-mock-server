import React from 'react';
import ReactDOM from 'react-dom';
import axios from 'axios';
import * as dotenv from 'dotenv';
import { Auth0Provider } from "@auth0/auth0-react";
import './index.css';
import App from './App';

import reportWebVitals from './reportWebVitals';

dotenv.config()

if (process.env.REACT_APP_API_URL) {
  axios.defaults.baseURL = process.env.REACT_APP_API_URL;
}

ReactDOM.render(
  <React.StrictMode>
    <Auth0Provider
      domain={process.env.REACT_APP_AUTH_DOMAIN || ""}
      clientId={process.env.REACT_APP_AUTH_CLIENT_ID || ""}
      audience={process.env.REACT_APP_AUTH_AUDIENCE}
      redirectUri={window.location.origin}
    >
      <App />
    </Auth0Provider>
  </React.StrictMode>,
  document.getElementById('root')
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
