import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';

// Lightweight JWT parser (no dependency) - parse payload only
function parseJwt(token) {
  if (!token) return null;
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join('')
    );

    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

const TokenWrapper = ({ children }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    const checkAndRefresh = async () => {
      const accessToken = localStorage.getItem('accessToken');
      const refreshToken = localStorage.getItem('refreshToken');

      const isAccessValid = () => {
        if (!accessToken) return false;
        const decoded = parseJwt(accessToken);
        if (!decoded || !decoded.exp) return false;
        const expiry = decoded.exp * 1000;
        return Date.now() < expiry;
      };

      if (isAccessValid()) {
        if (mounted) setLoading(false);
        return;
      }

      // Access token invalid/expired -> try refresh
      if (!refreshToken) {
        // no refresh token -> force login
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('username');
        navigate('/login');
        return;
      }

      try {
        const resp = await api.post('/refresh_token', { refreshToken });
        localStorage.setItem('accessToken', resp.data.accessToken);
        localStorage.setItem('refreshToken', resp.data.refreshToken);
        // update default header for api instance
        api.defaults.headers.common['Authorization'] = 'Bearer ' + resp.data.accessToken;
        if (mounted) setLoading(false);
      } catch (err) {
        // refresh failed -> clear storage and redirect to login
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('username');
        navigate('/login');
      }
    };

    checkAndRefresh();

    return () => {
      mounted = false;
    };
  }, [navigate]);

  if (loading) return null; // or a spinner component
  return <>{children}</>;
};

export default TokenWrapper;
