function login() {
    const authForm = $('#authForm');
    // Remove fields with empty values from post data
    authForm.find(':input').each(function () {
        if ($(this).val() === '') {
            $(this).attr('disabled', true);
        }
    });
    authForm.submit();
}

$('#loginBtn').click(function() {
    login();
})

