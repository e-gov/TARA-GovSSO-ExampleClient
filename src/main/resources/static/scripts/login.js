function login() {
    const authForm = document.getElementById('authForm');
    const inputs = authForm.querySelectorAll('input, select, textarea');

    // Remove fields with empty values from post data.
    inputs.forEach((input) => {
        if (input.value === '') {
            input.disabled = true;
        }
    });

    authForm.submit();
}

document.getElementById('loginBtn').addEventListener('click', login);
