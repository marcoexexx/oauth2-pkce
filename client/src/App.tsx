function App() {
  function handleOnClick() {
    window.location.href = "http://localhost:7891/oauth/login?redirect=/home"
  }

  return (
    <>
      <button onClick={handleOnClick}>Login</button>
    </>
  )
}

export default App
