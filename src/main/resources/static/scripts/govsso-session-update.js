const GOVSSO_SESSION_UPDATE_BUFFER_SECONDS = 2 * 60;
const RETRY_BUFFER_SECONDS = 10;

var sessionLengthInSeconds;
var sessionTimer;
var timeout;
var endTime;

function getById(id) {
    return document.getElementById(id);
}

function setElementText(id, value) {
    var element = getById(id);
    if (element) {
        element.textContent = value;
    }
}

function setElementValue(id, value) {
    var element = getById(id);
    if (element) {
        element.value = value;
    }
}

function setError(message, visible) {
    var errorElement = getById('error');
    if (!errorElement) {
        return;
    }
    errorElement.textContent = message;
    errorElement.classList.toggle('d-none', !visible);
}

window.addEventListener('load', function() {
    var isChecked = localStorage.getItem('isChecked');
    var autoUpdate = getById('autoUpdate');
    var updateButton = getById('updateButton');

    if (isChecked == 'false') {
        autoUpdate.checked = false;
    } else {
        autoUpdate.checked = true;
    }

    autoUpdate.addEventListener('change', function() {
        if (autoUpdate.checked) {
            localStorage.setItem('isChecked', 'true');
        } else {
            localStorage.setItem('isChecked', 'false');
        }
    });
    updateButton.addEventListener('click', updateGovSsoSession);

    sessionLengthInSeconds = Number.parseInt(getById('updateTimer').textContent, 10);
    endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds;
    timeout = setTimeout(autoUpdateGovSsoSession, sessionLengthInSeconds * 1000);
    sessionTimer = setInterval(incrementSeconds, 1000);
});

//TODO find a way to use leader election for browser tabs to prevent automatic session updates on multiple tabs
function updateGovSsoSession() {
    getById('updateButton').disabled = true;
    const csrfToken = document.querySelector('meta[name="_csrf"]').content;
    const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;
    var scope = '';
    if (getById('scope').value) {
        scope = '?scope=' + encodeURIComponent(getById('scope').value);
    }
    (async () => {
        await fetch('/oauth2/refresh/govsso' + scope, {
            method: 'POST',
            headers: {
                [csrfHeader]: csrfToken,
            },
            redirect: 'manual'
        }).then(async function (response) {
            if (response.ok) {
                const responseBody = await response.json();
                const claimsTableBody = getById('claimsTableBody');
                const rows = [];

                setElementText('id_token', responseBody.id_token);
                setElementValue('id_token_hint', responseBody.id_token);
                setElementText('access_token', responseBody.access_token);
                setElementText('refresh_token', responseBody.refresh_token);

                Object.entries(responseBody.id_token_claims).forEach(function(entry) {
                    const row = document.createElement('tr');
                    const keyCell = document.createElement('td');
                    const valueCell = document.createElement('td');

                    keyCell.textContent = entry[0];
                    valueCell.textContent = entry[1];
                    row.append(keyCell, valueCell);
                    rows.push(row);
                });
                claimsTableBody.replaceChildren(...rows);
                setError('', false);

                sessionLengthInSeconds = responseBody.time_until_govsso_session_expiration_in_seconds;
                clearInterval(sessionTimer);
                endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS;
                sessionTimer = setInterval(incrementSeconds, 1000);
                clearTimeout(timeout);
                timeout = setTimeout(autoUpdateGovSsoSession, (sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS) * 1000);

                setError('', false);
                getById('updateButton').disabled = false;
            } else {
                setError('Error updating GovSSO session. Refresh token is expired.', true);
                clearTimeout(timeout);
                getById('updateButton').disabled = false;
            }
        }).catch((error) => {
            setError('Error updating GovSSO session: ' + error.message + ' Retrying.', true);
            getById('updateButton').disabled = false;
            clearTimeout(timeout);
            timeout = setTimeout(autoUpdateGovSsoSession, RETRY_BUFFER_SECONDS * 1000);
        });
    })();
}

function incrementSeconds() {
    var timeUntilSessionUpdateInSeconds = endTime - getCurrentTimeStampInSeconds();

    if (timeUntilSessionUpdateInSeconds >= 0) {
        getById('updateTimer').textContent = timeUntilSessionUpdateInSeconds;
    } else {
        clearInterval(sessionTimer);
    }
}

function autoUpdateGovSsoSession() {
    if (getById('autoUpdate').checked) {
        updateGovSsoSession();
    }
}

function getCurrentTimeStampInSeconds() {
    return Math.floor(Date.now() / 1000);
}
