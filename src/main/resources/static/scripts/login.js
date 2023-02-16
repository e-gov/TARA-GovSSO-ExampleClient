$('#localeOptions').change(function () {
    var optionValue = $(this).val();
    if (optionValue === 'none') {
        removeParameter('locale')
    } else {
        updateParameter('locale', optionValue)
    }
});

$('#acrOptions').change(function () {
    var optionValue = $(this).val();
    if (optionValue === 'none') {
        removeParameter('acr')
    } else {
        updateParameter('acr', optionValue)
    }
});

$('#requestPhoneScope').change(function () {
    if($('#requestPhoneScope').is(':checked')){
        updateParameter('scope', 'phone')
    } else {
        removeParameter('scope')
    }
});

function removeParameter(parameter) {
    var queryString = $('#loginUrl').prop('search')
    urlParams = new URLSearchParams(queryString);
    urlParams.delete(parameter)
    $('#loginUrl').prop('search', urlParams)
}

function updateParameter(parameter, value) {
    var queryString = $('#loginUrl').prop('search')
    urlParams = new URLSearchParams(queryString);
    urlParams.set(parameter, value)
    $('#loginUrl').prop('search', urlParams)
}

