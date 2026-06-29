import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./index.css";

// Thème : sombre par défaut, suit la préférence système.
const sombre = window.matchMedia("(prefers-color-scheme: light)").matches ? "clair" : "sombre";
document.documentElement.setAttribute("data-theme", sombre);

const racine = document.getElementById("racine");
if (!racine) {
  throw new Error("Élément racine introuvable");
}

ReactDOM.createRoot(racine).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
