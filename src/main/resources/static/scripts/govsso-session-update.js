function updateGovssoSession() {
    (async () => {
        await fetch("/oauth2/authorization/govsso?prompt=none", {
            method: 'GET',
            // Makes sure cross-site requests (redirects to GOVSSO) are made with cookies, authorization headers
            // and TLS client certificates. GOVSSO needs only cookies.
            credentials: 'include'
        }).catch((error) => {
            // TODO: Handle error
            console.error('Error updating govsso session:', error);
        });
    })();
}
