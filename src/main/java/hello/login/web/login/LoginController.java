package hello.login.web.login;

import hello.login.domain.login.LoginService;
import hello.login.domain.member.Member;
import hello.login.web.SessionConst;
import hello.login.web.session.SessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {
    private final LoginService loginService;
    private final SessionManager sessionManager;

    @GetMapping("/login")
    public String loginForm(@ModelAttribute("loginForm") LoginForm form) {
        return "login/loginForm";
    }


    /**
     * 쿠키를 이용한 로그인
     * @param form 커맨드 객체
     * @param bindingResult 에러 저장
     * @param response 쿠키 저장
     * @return
     */
//    @PostMapping("/login")
//    public String login(@Validated @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletResponse response) {
//
//        if (bindingResult.hasErrors()) {
//            return "login/loginForm";
//        }
//
//        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());
//
//        if (loginMember == null) {
//            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
//            return "login/loginForm";
//        }
//
//        Cookie idCookie = new Cookie("memberId", String.valueOf(loginMember.getId()));
//        response.addCookie(idCookie);
//
//        return "redirect:/";
//    }

    /**
     * 직접만든 세션을 이용한 로그인
     * @param form 커맨드 객체
     * @param bindingResult 에러 저장
     * @param response 쿠키 저장
     * @return
     */
//    @PostMapping("/login")
//    public String login(@Validated @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletResponse response) {
//
//        if (bindingResult.hasErrors()) {
//            return "login/loginForm";
//        }
//
//        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());
//
//        if (loginMember == null) {
//            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
//            return "login/loginForm";
//        }
//
//        sessionManager.createSession(loginMember, response);
//
//        return "redirect:/";
//    }

    /**
     * HTTP 세션을 이용한 로그인
     * @param form 커맨드 객체
     * @param bindingResult 에러 저장
     * @param request
     * @return
     */
//    @PostMapping("/login")
//    public String login(@Validated @ModelAttribute LoginForm form, BindingResult bindingResult, HttpServletRequest request) {
//
//        if (bindingResult.hasErrors()) {
//            return "login/loginForm";
//        }
//
//        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());
//
//        if (loginMember == null) {
//            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
//            return "login/loginForm";
//        }
//
//        HttpSession session = request.getSession();
//        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
//
//        return "redirect:/";
//    }


    /**
     * HTTP 세션을 이용한 로그인, 요청 화면 기억
     * @param form 커맨드 객체
     * @param bindingResult 에러 저장
     * @param redirectURL 미인증 사용자 요청 시 로그인으로 redirect 하면서 쿼리스트링으로 요청한 url을 넘기는데, 그 url을 RequestParam으로 받음
     * @param request HTTP 요청
     * @return
     */
    @PostMapping("/login")
    public String login(@Validated @ModelAttribute LoginForm form, BindingResult bindingResult,
                        @RequestParam(defaultValue = "/") String redirectURL,
                        HttpServletRequest request) {

        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }

        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호가 맞지 않습니다.");
            return "login/loginForm";
        }

        HttpSession session = request.getSession();
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);

        return "redirect:" + redirectURL;
    }


    /**
     * 로그아웃
     * @param response 쿠키 저장
     * @return
     */
//    @PostMapping("/logout")
//    public String logout(HttpServletResponse response) {
//        expireCookie(response, "memberId");
//        return "redirect:/";
//    }

    /**
     * 로그아웃
     * @param request
     * @return
     */
//    @PostMapping("/logout")
//    public String logout(HttpServletRequest request) {
//        sessionManager.expire(request);
//        return "redirect:/";
//    }

    /**
     * 로그아웃
     * @param request
     * @return
     */
    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession();

        if (session != null) {
            session.invalidate();
        }

        return "redirect:/";
    }

    /**
     * 쿠키 만료
     * @param response 쿠키 저장
     * @param cookieName 쿠키 이름
     */
    private static void expireCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
