package ee.ria.govsso.client;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ClientController {

    public static final String LOGIN_VIEW_MAPPING = "/login";
    public static final String RESPONSE_MAPPING = "/dashboard";

    @Value("${spring.application.name}")
    private String applicationName;
    @Value("${sso.application.logo}")
    private String applicationLogo;

    @GetMapping(value = LOGIN_VIEW_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView clientLoginView() {

        ModelAndView model = new ModelAndView("loginView");
        model.addObject("application_name", applicationName);
        model.addObject("application_logo", applicationLogo);
        return model;
    }

    @GetMapping(value = RESPONSE_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView clientResponse() {

        ModelAndView model = new ModelAndView("dashboard");
        model.addObject("application_name", applicationName);
        model.addObject("application_logo", applicationLogo);
        return model;
    }

}
