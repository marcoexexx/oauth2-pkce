import axios from "axios"
import { useEffect, useState } from "react"
import { getCsrfToken } from "./utils";

const api = axios.create({
  baseURL: "http://localhost:7891",
  withCredentials: true,
})

api.interceptors.request.use(async (cfg) => {
  const csrfToken = await getCsrfToken();
  cfg.headers["X-XSRF-TOKEN"] = csrfToken;
  return cfg
})

function App() {
  const [todos, setTodos] = useState<any>([])
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [refreshFlag, setRefreshFlag] = useState(false)

  useEffect(() => {
    api.get("/me")
    .then(() => setIsAuthorized(true))
    .catch(() => setIsAuthorized(false))
  }, [])

  useEffect(() => {
    api.get("/todos")
      .then(res => setTodos(res.data.results ?? []))
      .catch(err => console.log("TODOS ->>", err?.message, err?.response?.data))
  }, [refreshFlag])

  function handleOnClick() {
    window.location.href = "http://localhost:7891/oauth/login?redirect=/home"
  }

  function handleComplete(todo: any) {
    return (evt: React.MouseEvent<HTMLButtonElement>) => {
      evt.preventDefault();
      api.post("/todos/"+todo.id, { completed: !todo.completed })
        .then(() => setRefreshFlag(!todo.completed))
        .catch(err => console.error(err?.response?.data))
    }
  }

  return (
    <>
      {!isAuthorized ? <button onClick={handleOnClick}>Login</button> : null}

      <ul>
        {todos.map((todo: any) => (
          <li key={todo.id}>
            <p>
              {todo.title} - {todo.completed ? "DONE" : "PROGRES"}
              <button onClick={handleComplete(todo)}>{!todo.completed ? "DONE" : "COMPLETE"}</button>
            </p>
          </li>
        ))}
      </ul>
    </>
  )
}

export default App
