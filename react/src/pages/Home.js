import React, { useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../auth/AuthProvider';

export default function Home() {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { user } = useAuth();

  useEffect(() => {
    const fetchData = async () => {
      try {
  // Fetch the protected endpoint
  const response = await api.get('/api/protected-message');
  setMessage(response.data);
  setError(null);
      } catch (err) {
        console.error('Error fetching home data:', err);
        setError(err?.response?.data?.message || err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div style={{ padding: '1rem' }}>
      <h2 style={{ marginBottom: '1rem' }}>Home</h2>
      <div style={{ marginBottom: '1rem' }}>
        Welcome, <strong>{user?.username || 'anonymous'}</strong>!
      </div>
      
      {loading ? (
        <div>Loading...</div>
      ) : error ? (
        <div style={{ color: 'red', padding: '1rem', background: '#fee', borderRadius: '4px' }}>
          Error: {error}
        </div>
      ) : (
        <div style={{ 
          padding: '1rem', 
          background: '#f8f9fa', 
          borderRadius: '4px',
          border: '1px solid #dee2e6'
        }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
            {typeof message === 'object' ? JSON.stringify(message, null, 2) : message}
          </pre>
        </div>
      )}
    </div>
  );
}
