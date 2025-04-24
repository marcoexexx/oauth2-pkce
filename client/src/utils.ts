import axios from "axios";

export function getCookie(name: string) {
  return document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'))?.[2]
}

export async function getCsrfToken() {
  return await axios.get("http://localhost:7891/oauth/csrf-token", { withCredentials: true }).then(res => res.data.state)
}
