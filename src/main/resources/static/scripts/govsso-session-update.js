function updateGovSsoSession() {
    const csrfToken = $("meta[name='_csrf']").attr("content");
    const csrfHeader = $("meta[name='_csrf_header']").attr("content");
    (async () => {
        await fetch('/oauth2/refresh/govsso', {
            method: 'POST',
            headers: {
                [csrfHeader]: csrfToken,
            }
        }).then(async function (response) {
            if (response.ok) {
                const idToken = await response.json();
                $("#id_token").text(idToken.id_token);
                $("#jti").text(idToken.jti);
                $("#iss").text(idToken.iss);
                $("#aud").text(idToken.aud);
                $("#exp").text(idToken.exp);
                $("#iat").text(idToken.iat);
                $("#sub").text(idToken.sub);
                $("#birthdate").text(idToken.birthdate);
                $("#given_name").text(idToken.given_name);
                $("#family_name").text(idToken.family_name);
                $("#amr").text(idToken.amr);
                $("#nonce").text(idToken.nonce);
                $("#acr").text(idToken.acr);
                $("#at_hash").text(idToken.at_hash);
                $("#sid").text(idToken.sid);
                $("#error").hide();
            } else {
                $("#error").show();
                $("#error").text('Error updating GovSSO session. Refresh token is expired.');
            }
        }).catch((error) => {
            $("#error").show();
            $("#error").text('Error updating GovSSO session: ' + error.message);
        });
    })();
}
