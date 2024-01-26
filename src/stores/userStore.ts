import { create } from "zustand";

import { persist, devtools } from "zustand/middleware";

// Define the structure of the user object
export interface User {
  id?: string;
  fullname: string;
  email?: string;
  bio?: string;
  image?: string;
}

// Define methods that can be used to modify the state
export interface UserActions {
  setUser: (user: User) => void;
  logout: () => void;
}

// Create a Zustand store combining User and UserActions
// Apply devtools middleware for better debugging
// Apply persist middleware to persist state to storage
// Callback function to initialize and modify the state
// Initial state

export const useUserStore = create<User & UserActions>()(
  devtools(
    persist(
      (set) => ({
        id: "",
        fullname: "",
        email: "",
        bio: "",
        image: "",

        setUser: (user) => set(user), // Method to set user data
        logout: () => {
          // Method to reset user data (simulate logout)
          set({ id: "", fullname: "", email: "", bio: "", image: "" });
        },
      }),
      {
        name: "user-storage", // Configuration for persist middleware
      }
    )
  )
);
