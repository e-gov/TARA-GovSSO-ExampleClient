function updateGovSsoSession() {
    (async () => {
        await fetch('/oauth2/authorization/govsso?prompt=none', {
            method: 'GET',
            // Makes sure cross-site requests (redirects to GovSSO) are made with cookies, authorization headers
            // and TLS client certificates. GovSSO needs only cookies.
            credentials: 'include'
        }).then(function (response) {
            if (response.ok) {
                console.log('GovSSO session successfully updated');
            } else {
                console.error('Error updating GovSSO session');
            }
        }).catch((error) => {
            // TODO: Handle error
            console.error('Error updating GovSSO session:', error);
        });
    })();
}
