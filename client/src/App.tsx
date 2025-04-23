import axios from "axios"
import { useEffect, useState } from "react"

const api = axios.create({
  baseURL: "http://localhost:7891",
  withCredentials: true,
})

api.interceptors.request.use(async (cfg) => {
  return cfg
})

function App() {
  const [todos, setTodos] = useState<any>([])

  useEffect(() => {
    api.get("/todos")
      .then(res => setTodos(res.data.results ?? []))
      .catch(err => console.log("TODOS ->>", err?.message, err?.response?.data))
  }, [])

  function handleOnClick() {
    window.location.href = "http://localhost:7891/oauth/login?redirect=/home"
  }

  return (
    <>
      <button onClick={handleOnClick}>Login</button>

      <ul>
        {todos.map((todo: any) => (
          <li key={todo.id}>
            <p>{todo.title}</p>
          </li>
        ))}
      </ul>
    </>
  )
}

export default App
