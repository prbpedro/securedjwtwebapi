using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecuredJwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        private string GetUserData()
        {
            string claims = string.Empty;
            foreach(Claim c in HttpContext.User.Claims)
            {
                claims+=string.Format("(Type: {0}, value: {1}), ", c.Type, c.Value);
            }

            string userData = string.Format(
                "name: {0}, authenticated: {1}, claims:({2})", 
                HttpContext.User.Identity.Name, 
                HttpContext.User.Identity.IsAuthenticated, 
                claims);
            
            return userData;
        }

        [HttpGet]
        [Authorize("Bearer")]
        [Authorize(Roles = "administrador")]
        [Route("administrador")]
        public IActionResult MetodoSeguroAdministrador()
        {
            return Ok
            (
                new 
                { 
                    Mensagem = string.Format(
                        "Método que somente token com usuário com role 'administrador' pode acessar. USUARIO: {0}",
                        GetUserData()
                    )
                }
            );
        }

        [HttpGet]
        [Authorize("Bearer")]
        [Authorize(Roles = "usuario")]
        [Route("usuario")]
        public IActionResult MetodoSeguroUsuario()
        {
            return Ok
            (
                new 
                { 
                    Mensagem = string.Format(
                        "Método que somente token com usuário com role 'usuario' pode acessar. USUARIO: {0}",
                        GetUserData()
                    )
                }
            );
        }
    }
}
