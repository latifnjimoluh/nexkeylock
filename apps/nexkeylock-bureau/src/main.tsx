import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { initialiserTheme } from "./lib/theme";
import "./index.css";

initialiserTheme();

const racine = document.getElementById("racine");
if (!racine) {
  throw new Error("Élément racine introuvable");
}

ReactDOM.createRoot(racine).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
