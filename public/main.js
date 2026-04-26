const form = document.getElementById('loginForm')
const email = document.getElementById('email')
const password = document.getElementById('password')

console.log('main.js loaded')

form.addEventListener('submit', async (event) => {
  event.preventDefault()

  if (email.value === '' || password.value === '') {
    alert('Please fill all fields')
    return
  }

  const response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: email.value,
      password: password.value
    })
  })

  const result = await response.json()

  if (!response.ok) {
    alert(result.message)
  } else {
    localStorage.setItem('isLoggedIn', 'true')
    window.location.href = 'dashboard.html'
  }
})
