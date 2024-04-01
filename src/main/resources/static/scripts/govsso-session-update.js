const GOVSSO_SESSION_UPDATE_BUFFER_SECONDS = 2 * 60;
const RETRY_BUFFER_SECONDS = 10;

var sessionLengthInSeconds;
var sessionTimer;
var timeout;
var endTime;

$(window).on('load', function() {
    var isChecked = localStorage.getItem('isChecked');

    if (isChecked == 'false') {
        $('#autoUpdate').prop('checked', false);
    } else {
        $('#autoUpdate').prop('checked', true);
    }

    $('#autoUpdate').change(function () {
        if($('#autoUpdate').is(':checked')){
            localStorage.setItem('isChecked', 'true');
        } else {
            localStorage.setItem('isChecked', 'false');
        }
    });
    $('#updateButton').click(updateGovSsoSession);

    sessionLengthInSeconds = +$('#updateTimer').text();
    endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds;
    timeout = setTimeout(autoUpdateGovSsoSession, sessionLengthInSeconds * 1000);
    sessionTimer = setInterval(incrementSeconds, 1000);
});

//TODO find a way to use leader election for browser tabs to prevent automatic session updates on multiple tabs
function updateGovSsoSession() {
    $('#updateButton').prop('disabled',true);
    const csrfToken = $('meta[name="_csrf"]').attr('content');
    const csrfHeader = $('meta[name="_csrf_header"]').attr('content');
    var scope = '';
    if ($('#scope').val()) {
        scope = '?scope=' + encodeURIComponent($('#scope').val());
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
                const idToken = await response.json();

                $('#id_token').text(idToken.id_token);
                $('#access_token').text(idToken.access_token);
                $('#refresh_token').text(idToken.refresh_token);
                $('#jti').text(idToken.jti);
                $('#iss').text(idToken.iss);
                $('#aud').text(idToken.aud);
                $('#exp').text(idToken.exp);
                $('#iat').text(idToken.iat);
                $('#sub').text(idToken.sub);
                $('#birthdate').text(idToken.birthdate);
                $('#given_name').text(idToken.given_name);
                $('#family_name').text(idToken.family_name);
                $('#amr').text(idToken.amr);
                $('#nonce').text(idToken.nonce);
                $('#acr').text(idToken.acr);
                $('#at_hash').text(idToken.at_hash);
                $('#sid').text(idToken.sid);
                $('#error').hide();

                sessionLengthInSeconds = idToken.time_until_govsso_session_expiration_in_seconds;
                clearInterval(sessionTimer);
                endTime = getCurrentTimeStampInSeconds() + sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS;
                sessionTimer = setInterval(incrementSeconds, 1000);
                clearTimeout(timeout);
                timeout = setTimeout(autoUpdateGovSsoSession, (sessionLengthInSeconds - GOVSSO_SESSION_UPDATE_BUFFER_SECONDS) * 1000);

                $('#error').hide();
                $('#updateButton').prop('disabled',false);
            } else {
                $('#error').show();
                $('#error').text('Error updating GovSSO session. Refresh token is expired.');
                clearTimeout(timeout);
                $('#updateButton').prop('disabled',false);
            }
        }).catch((error) => {
            $('#error').show();
            $('#error').text('Error updating GovSSO session: ' + error.message + ' Retrying.');
            $('#updateButton').prop('disabled',false);
            clearTimeout(timeout);
            timeout = setTimeout(autoUpdateGovSsoSession, RETRY_BUFFER_SECONDS * 1000);
        });
    })();
}

function incrementSeconds() {
    var timeUntilSessionUpdateInSeconds = endTime - getCurrentTimeStampInSeconds();

    if (timeUntilSessionUpdateInSeconds >= 0) {
        $('#updateTimer').text(timeUntilSessionUpdateInSeconds);
    } else {
        clearInterval(sessionTimer);
    }
}

function autoUpdateGovSsoSession() {
    if($('#autoUpdate').prop('checked')) {
        updateGovSsoSession();
    }
}

function getCurrentTimeStampInSeconds() {
    return Math.floor(Date.now() / 1000);
}
