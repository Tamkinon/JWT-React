import React, { createContext, useContext, useEffect, useState } from 'react';
import api from '../api/axios';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const token = sessionStorage.getItem('accessToken');
    const username = sessionStorage.getItem('username');
    if (token && username) {
      setUser({ username });
    }
  }, []);

  const login = async (username, password) => {
    try {
      const resp = await api.post('/login', { username, password });
      sessionStorage.setItem('accessToken', resp.data.accessToken);
      sessionStorage.setItem('refreshToken', resp.data.refreshToken);
      sessionStorage.setItem('username', resp.data.username);
      setUser({ username: resp.data.username });
      navigate('/');
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  };

  const logout = () => {
    sessionStorage.removeItem('accessToken');
    sessionStorage.removeItem('refreshToken');
    sessionStorage.removeItem('username');
    setUser(null);
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
