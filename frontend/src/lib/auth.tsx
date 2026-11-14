"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import { getMe, login as apiLogin, verifyLoginOTP } from "./api";

interface User {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  organization_id: number;
  tenant_id: number;
  status: string;
  last_login_at: string | null;
  permissions: string[];
  tenant_name: string | null;
  organization_name: string | null;
  totp_enabled?: boolean;
  setup_completed?: boolean;
  email_verified?: boolean;
  organizations?: Array<{
    organization_id: number;
    organization_name: string;
    role_in_org: string;
    is_active: boolean;
  }>;
}

interface MfaChallenge {
  mfa_required?: boolean;
  mfa_setup_required?: boolean;
  mfa_token: string;
  totp_uri?: string;
  qr_code?: string;
  user_id?: number;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  mfaChallenge: MfaChallenge | null;
  login: (email: string, password: string, remember?: boolean) => Promise<boolean>;
  verifyMfa: (code: string, remember?: boolean) => Promise<void>;
  clearMfa: () => void;
  setAuth: (token: string, user: User) => void;
  logout: () => void;
  refreshUser: () => Promise<void>;
  hasPermission: (resource: string, action: string) => boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  isLoading: true,
  mfaChallenge: null,
  login: async () => false,
  verifyMfa: async () => {},
  clearMfa: () => {},
  setAuth: () => {},
  logout: () => {},
  refreshUser: async () => {},
  hasPermission: () => false,
  isAdmin: false,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [mfaChallenge, setMfaChallenge] = useState<MfaChallenge | null>(null);
  const [rememberPref, setRememberPref] = useState(false);
  // Ref stores mfa_token synchronously — immune to React's async state batching
  const mfaTokenRef = useRef<string | null>(null);
  const mfaVerifyingRef = useRef(false);

  const logout = useCallback(() => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    sessionStorage.removeItem("token");
    sessionStorage.removeItem("user");
    setToken(null);
    setUser(null);
    window.location.href = "/login";
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const u = await getMe();
      setUser(u);
      localStorage.setItem("user", JSON.stringify(u));
    } catch {
      logout();
    }
  }, [logout]);

  const setAuth = useCallback((t: string, u: User) => {
    localStorage.setItem("token", t);
    localStorage.setItem("user", JSON.stringify(u));
    setToken(t);
    setUser(u);
  }, []);

  const clearMfa = useCallback(() => {
    mfaTokenRef.current = null;
    setMfaChallenge(null);
  }, []);

  const login = useCallback(async (email: string, password: string, remember = false): Promise<boolean> => {
    setRememberPref(remember);
    const res = await apiLogin(email, password);

    // 2FA required — store token in ref immediately (synchronous, no batching delay)
    if (res.mfa_required || res.mfa_setup_required) {
      mfaTokenRef.current = (res as MfaChallenge).mfa_token;
      setMfaChallenge(res as MfaChallenge);
      return true; // MFA needed
    }

    // No 2FA — normal flow
    const t = res.access_token;
    const store = remember ? localStorage : sessionStorage;
    store.setItem("token", t);
    setToken(t);
    const u = await getMe();
    setUser(u);
    store.setItem("user", JSON.stringify(u));
    return false; // no MFA
  }, []);

  const verifyMfa = useCallback(async (code: string, remember?: boolean) => {
    // Read token from ref (synchronous) — avoids stale closure over React state
    const token = mfaTokenRef.current;
    if (!token) throw new Error("No MFA session");
    if (mfaVerifyingRef.current) throw new Error("Verification already in progress");
    mfaVerifyingRef.current = true;
    try {
      const res = await verifyLoginOTP(token, code);
      const t = res.access_token;
      const store = (remember ?? rememberPref) ? localStorage : sessionStorage;
      store.setItem("token", t);
      setToken(t);
      const u = await getMe();
      setUser(u);
      store.setItem("user", JSON.stringify(u));
      mfaTokenRef.current = null;
      setMfaChallenge(null);
    } finally {
      mfaVerifyingRef.current = false;
    }
  }, [rememberPref]);

  useEffect(() => {
    const storedToken = localStorage.getItem("token") || sessionStorage.getItem("token");
    if (storedToken) {
      setToken(storedToken);
      const storedUser = localStorage.getItem("user") || sessionStorage.getItem("user");
      if (storedUser) {
        try {
          setUser(JSON.parse(storedUser));
        } catch {
          /* ignore */
        }
      }
      getMe()
        .then((u) => {
          setUser(u);
          const store = localStorage.getItem("token") ? localStorage : sessionStorage;
          store.setItem("user", JSON.stringify(u));
        })
        .catch(() => {
          localStorage.removeItem("token");
          localStorage.removeItem("user");
          sessionStorage.removeItem("token");
          sessionStorage.removeItem("user");
          setToken(null);
          setUser(null);
        })
        .finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const hasPermission = useCallback((resource: string, action: string) => {
    if (!user) return false;
    const adminRoles = ["admin", "superadmin", "platform_admin"];
    if (adminRoles.includes(user.role)) return true;
    const perms = user.permissions || [];
    return perms.includes(`${resource}:${action}`) || perms.includes(`${resource}:manage`) || perms.includes("*:*");
  }, [user]);

  const isAdmin = user ? ["admin", "superadmin", "platform_admin", "tenant_admin"].includes(user.role) : false;

  return (
    <AuthContext.Provider value={{ user, token, isLoading, mfaChallenge, login, verifyMfa, clearMfa, setAuth, logout, refreshUser, hasPermission, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
}

export const ADMIN_ROLES = ["admin", "platform_admin", "superadmin", "super_admin"];

export function isAdminUser(user: { role: string } | null): boolean {
  return user ? ADMIN_ROLES.includes(user.role) : false;
}

export function useAuth() {
  return useContext(AuthContext);
}
