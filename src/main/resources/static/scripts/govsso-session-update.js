function updateGovssoSession() {
    (async () => {
        await fetch("/oauth2/authorization/govsso?prompt=none", {
            method: 'GET',
            // Makes sure cross-site requests (redirects to GOVSSO) are made with cookies, authorization headers
            // and TLS client certificates. GOVSSO needs only cookies.
            credentials: 'include'
        }).then(function (response) {
            if (response.ok) {
                console.log('GOVSSO session successfully updated');
            } else {
                console.error('Error updating GOVSSO session');
            }
        }).catch((error) => {
            // TODO: Handle error
            console.error('Error updating GOVSSO session:', error);
        });
    })();
}
