import { Routes, Route } from "react-router-dom"
import Home from "./pages/Home"
import Login from "./pages/Login"
import ResetPassword from "./pages/ResetPassword"
import EmailVerify from "./pages/EmailVerify"
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const App = () => {
  return (
    <div>
      <ToastContainer />
      <Routes>
        <Route path="/" element={<Home/>} />
        <Route path="/login" element={<Login/>} />
        <Route path="/email-verify" element={<EmailVerify/>} />  
        <Route path="/reset-password" element={<ResetPassword/>} />  
      </Routes>
    </div>
  )
}

export default App

