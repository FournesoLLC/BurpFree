import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { applyTheme, readMode, resolveTheme } from "./theme";
import "./styles.css";

// Stamp the saved / system theme on <html> *before* the first paint so
// there's no FOUC transition from the default dark palette to light.
applyTheme(resolveTheme(readMode()));

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
