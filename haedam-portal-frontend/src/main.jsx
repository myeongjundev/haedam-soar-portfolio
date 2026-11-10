import React from "react";
import { createRoot } from "react-dom/client";
import {
  createBrowserRouter,
  createRoutesFromElements,
  RouterProvider,
  Route,
} from "react-router-dom";
import { AuthProvider, Guard } from "./components/auth";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import AuthPage from "./pages/AuthPage";
import Petitions from "./pages/Petitions";
import NewPetition from "./pages/NewPetition";
import PetitionDetail from "./pages/PetitionDetail";
import Admin from "./pages/Admin";
import Account from "./pages/Account";
import { UnsavedChangesProvider } from "./components/UnsavedChanges";
import "./styles/main.css";
import "./styles/refresh.css";
import "./styles/workflows.css";
import "./styles/submission.css";
import "./styles/service-finder.css";
import "./styles/staff-workspace.css";
import "./styles/admin-directory.css";

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
      element={
        <UnsavedChangesProvider>
          <AuthProvider>
            <Layout />
          </AuthProvider>
        </UnsavedChangesProvider>
      }
    >
      <Route index element={<Home />} />
      <Route path="login" element={<AuthPage />} />
      <Route path="register" element={<AuthPage register />} />
      <Route
        path="petitions"
        element={
          <Guard roles={["citizen"]}>
            <Petitions />
          </Guard>
        }
      />
      <Route
        path="petitions/new"
        element={
          <Guard roles={["citizen"]}>
            <NewPetition />
          </Guard>
        }
      />
      <Route
        path="petitions/:id"
        element={
          <Guard roles={["citizen", "staff"]}>
            <PetitionDetail />
          </Guard>
        }
      />
      <Route
        path="work"
        element={
          <Guard roles={["staff"]}>
            <Petitions staff />
          </Guard>
        }
      />
      <Route
        path="admin"
        element={
          <Guard roles={["admin"]}>
            <Admin />
          </Guard>
        }
      />
      <Route
        path="account"
        element={
          <Guard>
            <Account />
          </Guard>
        }
      />
      <Route
        path="*"
        element={
          <section className="panel empty">
            <h1>페이지를 찾을 수 없습니다</h1>
            <a className="button primary" href="/">
              처음으로
            </a>
          </section>
        }
      />
    </Route>,
  ),
);
createRoot(document.getElementById("root")).render(
  <RouterProvider router={router} />,
);
