import React from 'react';
import { Routes, Route, Link, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth/AuthProvider';
import Login from './pages/Login';
import Home from './pages/Home';

// Protected Route Component
function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) {
    return <Navigate to="/login" />;
  }
  return children;
}

function Nav() {
  const { user, logout } = useAuth();
  return (
    <nav style={{ 
      padding: '1rem', 
      background: '#f0f0f0', 
      marginBottom: '1rem',
      borderRadius: '4px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }}>
      <div>
        <Link 
          to="/" 
          style={{ 
            marginRight: '1rem',
            textDecoration: 'none',
            color: '#0056b3'
          }}
        >
          Home
        </Link>
      </div>
      <div>
        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span>Welcome, {user.username}!</span>
            <button 
              onClick={logout}
              style={{
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                border: '1px solid #ccc',
                background: '#fff',
                cursor: 'pointer',
                transition: 'all 0.2s',
                ':hover': {
                  background: '#f0f0f0'
                }
              }}
            >
              Logout
            </button>
          </div>
        ) : (
          <Link 
            to="/login"
            style={{ 
              textDecoration: 'none',
              color: '#0056b3'
            }}
          >
            Login
          </Link>
        )}
      </div>
    </nav>
  );
}

function App() {
  return (
    <AuthProvider>
      <div style={{ 
        maxWidth: '800px', 
        margin: '0 auto', 
        padding: '1rem',
      }}>
        <Nav />
        <Routes>
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <Home />
              </ProtectedRoute>
            } 
          />
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </div>
    </AuthProvider>
  );
}

export default App;

