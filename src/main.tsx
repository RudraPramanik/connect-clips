import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import Feed from "./pages/Feed.tsx";
import Upload from "./pages/Upload.tsx";
import Profile from "./pages/profile.tsx";
import Post from "./pages/Post.tsx";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Feed />,
  },
  {
    path: "/upload",
    element: <Upload />,
  },
  {
    path: "/profile/:id",
    element: <Profile />,
  },
  {
    path:"/post/:id",
    element:<Post/>
  }
]);
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router}/>
    <App />
  </React.StrictMode>
);
