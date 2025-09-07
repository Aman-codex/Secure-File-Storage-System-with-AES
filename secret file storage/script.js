const fileInput = document.getElementById("fileInput");
const password = document.getElementById("password");
const confirmPassword = document.getElementById("confirmPassword");
const statusBox = document.getElementById("status");

document.getElementById("encryptBtn").addEventListener("click", () => {
  if (!fileInput.files[0]) {
    setStatus("❌ Please select a file to encrypt", "red");
    return;
  }
  if (!password.value || !confirmPassword.value) {
    setStatus("❌ Please enter and confirm a password", "red");
    return;
  }
  if (password.value !== confirmPassword.value) {
    setStatus("❌ Passwords do not match", "red");
    return;
  }

  // TODO: Send file + password to backend (Flask/FastAPI) for encryption
  setStatus("🔒 File ready to be encrypted (connect to backend).", "green");
});

document.getElementById("decryptBtn").addEventListener("click", () => {
  if (!fileInput.files[0]) {
    setStatus("❌ Please select a file to decrypt", "red");
    return;
  }
  if (!password.value) {
    setStatus("❌ Please enter your password", "red");
    return;
  }

  // TODO: Send file + password to backend (Flask/FastAPI) for decryption
  setStatus("🔓 File ready to be decrypted (connect to backend).", "green");
});

function setStatus(message, color) {
  statusBox.textContent = message;
  statusBox.style.color = color;
}
