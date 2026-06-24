/* eslint-disable react-refresh/only-export-components */
import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt?: string;
  created_at?: string;
}

const normalizeUser = (raw: any): User => ({
  id: raw.id,
  email: raw.email,
  name: raw.name,
  role: raw.role,
  createdAt: raw.createdAt || raw.created_at || new Date().toISOString(),
})

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
  error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Fetch user profile
      fetchUserProfile();
    } else {
      setIsLoading(false);
    }
  }, []);

  const fetchUserProfile = async () => {
    try {
      setError(null);
      const response = await axios.get<any>('/api/auth/profile');
      setUser(normalizeUser(response.data.success ? response.data.data : response.data));
    } catch {
      // Token might be invalid
      localStorage.removeItem('token');
      delete axios.defaults.headers.common['Authorization'];
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      setError(null);
      const response = await axios.post<any>('/api/auth/login', { email, password });
      const { token, user: userData } = response.data;

      localStorage.setItem('token', token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setUser(normalizeUser(userData));
    } catch (error: unknown) {
      const errorMessage = ((error as { response?: { data?: { message?: string; error?: string } } })?.response?.data?.message) ||
                           ((error as { response?: { data?: { message?: string; error?: string } } })?.response?.data?.error) ||
                           'Login failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const register = async (email: string, password: string, name: string) => {
    try {
      setError(null);
      const response = await axios.post<any>('/api/auth/register', { email, password, name });
      const { token, user: userData } = response.data;

      localStorage.setItem('token', token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setUser(normalizeUser(userData));
    } catch (error: unknown) {
      const errorMessage = ((error as { response?: { data?: { message?: string; error?: string } } })?.response?.data?.message) ||
                           ((error as { response?: { data?: { message?: string; error?: string } } })?.response?.data?.error) ||
                           'Registration failed';
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setError(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, isLoading, error }}>
      {children}
    </AuthContext.Provider>
  );
};