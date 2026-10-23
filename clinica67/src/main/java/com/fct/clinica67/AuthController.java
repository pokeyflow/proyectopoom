package com.fct.clinica67;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {

    private final UsuarioRepository repo;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthController(UsuarioRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/")
    public String raiz() { return "redirect:/login"; }

    @GetMapping("/login")
    public String loginForm() { return "login"; }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        HttpSession session, Model model) {
        var usuario = repo.findByUsername(username);
        if (usuario.isPresent() && encoder.matches(password, usuario.get().getPassword())) {
            session.setAttribute("usuario", username);
            return "redirect:/inicio";
        }
        model.addAttribute("error", "Usuario o contraseña incorrectos");
        return "login";
    }

    @GetMapping("/registro")
    public String registroForm() { return "registro"; }

    @PostMapping("/registro")
    public String registro(@RequestParam String username, @RequestParam String password, Model model) {
        if (repo.findByUsername(username).isPresent()) {
            model.addAttribute("error", "Ese usuario ya existe");
            return "registro";
        }
        var u = new Usuario();
        u.setUsername(username);
        u.setPassword(encoder.encode(password));
        repo.save(u);
        return "redirect:/login";
    }

    @GetMapping("/inicio")
    public String inicio(HttpSession session, Model model) {
        Object usuario = session.getAttribute("usuario");
        if (usuario == null) return "redirect:/login";
        model.addAttribute("usuario", usuario);
        return "inicio";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}