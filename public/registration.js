const form = document.getElementById('formContainer')

const fullName = document.getElementById('fullName')
const DateOfBirth = document.getElementById('DateOfBirth')
const userName = document.getElementById('userName')
const email = document.getElementById('email')
const password = document.getElementById('password')
const confirmPassword = document.getElementById('confirmPassword')

form.addEventListener('submit', async function (event) {
  event.preventDefault()

  if (
    fullName.value === '' ||
    DateOfBirth.value === '' ||
    userName.value === '' ||
    email.value === '' ||
    password.value === '' ||
    confirmPassword.value === ''
  ) {
    alert('Please fill in all fields.')
    return
  }

  if (password.value !== confirmPassword.value) {
    alert('Passwords do not match.')
    return
  }

  const response = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fullName: fullName.value,
      DateOfBirth: DateOfBirth.value,
      userName: userName.value,
      email: email.value,
      password: password.value
    })
  })

  const result = await response.json()

  if (!response.ok) {
    alert(result.message)
  } else {
    alert('Registration successful')
    window.location.href = 'main.html'
  }
})
