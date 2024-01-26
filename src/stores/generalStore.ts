import { create } from 'zustand';
import {persist, devtools} from "zustand/middleware"

export interface GeneralState{
    isLoginOpen: boolean
    isEditProfileOpen: boolean
    selectedPosts:null
    ids:null
    suggested: null
    posts: null
}

export interface GeneratActions{
    setLoginIsOpen: (isLoginOpen: boolean) => void
    setIsEditProfileOpen:()=>void;
}

export const userGeneralStore = create<GeneralState & GeneratActions>()(
    devtools(
        persist(
            (set) =>({
                isLoginOpen: false,
                isEditProfileOpen:false,
                selectedPosts:null,
                ids: null,
                suggested:null,
                posts: null,
                setLoginIsOpen:(isLoginOpen: boolean)=>{
                    set({
                        isLoginOpen
                    })
                },
                setIsEditProfileOpen: ()=>{
                    return set((state)=>({
                        isEditProfileOpen: !state.isEditProfileOpen,
                    }))
                },

            } ),
            {
                name: "general-storage",
              }
        )
    )
)