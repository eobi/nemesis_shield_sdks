// Servlet filter (Jakarta EE / Spring Boot 3+). Register it and set NEMESIS_TOKEN.
// Spring Boot:  @Bean FilterRegistrationBean<NemesisShieldFilter> ... new NemesisShieldFilter()
// Blocks off-baseline requests in enforce mode; records every request. Uses the same native
// NemesisShield client (local shape + policy cache + background poll) as the rest of the SDK.
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class NemesisShieldFilter implements Filter {
    private NemesisShield nemesis;

    @Override
    public void init(FilterConfig cfg) { nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN")); }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest r = (HttpServletRequest) req;
        HttpServletResponse w = (HttpServletResponse) res;
        String method = r.getMethod(), path = r.getRequestURI(), query = r.getQueryString();
        boolean authed = r.getHeader("Authorization") != null || r.getHeader("Cookie") != null;
        if (nemesis.enforcing()) {
            String reason = nemesis.decide(nemesis.shapeOf(method, path, query, authed));
            if (reason != null) {
                nemesis.observe(method, path, query, authed, 403);
                w.setStatus(403);
                w.setContentType("application/json");
                w.getWriter().write("{\"error\":\"blocked_by_nemesis_shield\",\"reason\":\"" + reason + "\"}");
                return;
            }
        }
        chain.doFilter(req, res);
        nemesis.observe(method, path, query, authed, w.getStatus());
    }
}
