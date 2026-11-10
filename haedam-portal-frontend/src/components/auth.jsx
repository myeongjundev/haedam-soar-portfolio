import { createContext, useContext, useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { api, setCsrf } from "../api/client";
import { ErrorBox, Loading } from "./ui";

const Auth = createContext(null);
export const useAuth = () => useContext(Auth);
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState(null);
  const refresh = async () => {
    setError(null);
    try {
      const result = await api("/auth/me");
      setUser(result.user);
      setReady(true);
    } catch (e) {
      setError(e);
    }
  };
  useEffect(() => {
    refresh();
    const expired = () => {
      setUser(null);
      setCsrf("");
    };
    window.addEventListener("auth-expired", expired);
    return () => window.removeEventListener("auth-expired", expired);
  }, []);
  const login = async (data) => {
    const result = await api("/auth/login", { method: "POST", data });
    setUser(result.user);
    return result.user;
  };
  const logout = async () => {
    await api("/auth/logout", { method: "POST" });
    setUser(null);
    await refresh();
  };
  return (
    <Auth.Provider value={{ user, setUser, refresh, login, logout }}>
      {error ? (
        <main className="startup-error">
          <h1>해담시청 민원포털</h1>
          <ErrorBox error={error} retry={refresh} />
        </main>
      ) : ready ? (
        children
      ) : (
        <Loading />
      )}
    </Auth.Provider>
  );
}
export function Guard({ roles, children }) {
  const { user } = useAuth();
  const location = useLocation();
  if (!user)
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname + location.search }}
      />
    );
  if (roles && !roles.includes(user.role))
    return (
      <section className="panel">
        <h1>접근 권한이 없습니다</h1>
        <p>현재 계정으로 이용할 수 없는 화면입니다.</p>
      </section>
    );
  return children;
}
