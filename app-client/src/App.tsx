import React from 'react';
import { Main } from './Main';
import './App.css';
import LoginButton from './LoginButton';
import LogoutButton from './LogoutButton';
import Profile from './Profile';
import { AuthProvider } from './helpers/AuthProvider';

function App() {
  return (
    <>
      <header>
        <nav>
          <LoginButton />
        </nav>
        <nav>
          <LogoutButton />
        </nav>
        <nav>
          <Profile />
        </nav>
      </header>
      <AuthProvider>
        <div className="App">
          <Main></Main>
        </div>
      </AuthProvider>
    </>
  );
}

export default App;
