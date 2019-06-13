# ASPNetCore - Web API com autorização baseada em roles fornecidos via Token JWT

Através deste tutorial iremos criar um projeto <b>web-api</b> com o <i>framework</i> <b>aspnetcore 2.2</b> que deverá disponibilizar dois métodos retornam as informações do usuário identificado via Token JWT caso o mesmo possua determinados Roles de acesso também identificados no Token.

A execução desta aplicação necessita que a data/hora da máquina tenha como fuso horário o valor UTC - Tempo Universal Coordenado.

## Criar um projeto web-api ASPNetCore 2.2

1. Abra uma pasta que deverá conter o projeto a ser criado
1. Crie um projeto web-api ASPNetCore 2.2 através do comando abaixo no terminal <b>Windows PowerShell</b> contido no <b>VS Code</b>.

	```csharp
    dotnet new webapi
	```
	
### Editar classe Program.cs
Incluir chamada ao método <i>UseUrls</i> no método <i>CreateWebHostBuilderconforme</i>. A execução deste método determina a URL de entrada do web-api e por padrão desabilita o HTTPS no Kestrel. Em um ambiente produtivo a aplicação deverá ser acessada via protocolo HTTPS.

```csharp
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseUrls("http://localhost:7000");
```

### Editar classe Startup.cs

#### Incluir construtor que habilita configuração via arquivo json

Incluir construtor conforme código abaixo habilitando assim a configuração do componente via arquivo json.

```csharp
public Startup(IHostingEnvironment env)
{
	HostingEnvironment = env;
	Configuration = new ConfigurationBuilder()
		.SetBasePath(env.ContentRootPath)
		.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
		.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: false)
		.AddEnvironmentVariables()
		.Build();
}
```

Incluir na raiz do projeto os arquivos:

1. appsettings.json

    ```json
	{
		"Logging": {
			"LogLevel": {
				"Default": "Warning"
			}
		},
			
		"AppSettings": 
		{
			"jwt": 
			{
				"key": "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
				"issuer": "http://localhost:6000/",
				"audiences": ["audience1","audience2"]
			}
		},
		
		"AllowedHosts": "*"
	}
    ```
    
2. appsettings.Development.json

	```json
	{
	}
    ```

Adicionar ao <i>csproj</i> da aplicação o ItemGroup abaixo para forçar a cópia dos arquivos para os diretórios de publicação.

```xml	
<ItemGroup>
	<none Include="appsettings.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
    <none Include="appsettings.Development.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
</ItemGroup>
```
	
#### Alterar método de configuração dos serviços de injetor de dependências

O método nomeado <i>ConfigureServices</i>, pertencente a classe <b>Startup.cs</b>, deverá ser alterado conforme código abaixo:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication((cfg =>
    {
        cfg.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        cfg.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }))
    .AddJwtBearer(options =>
    {   
        string[] audiences = Configuration.GetSection("AppSettings:jwt:audiences").Get<string[]>();

        if(HostingEnvironment.IsDevelopment())
        {
            options.RequireHttpsMetadata= false;
        }
        
        options.Configuration = new OpenIdConnectConfiguration();

        options.Authority = Configuration["AppSettings:jwt:issuer"];
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Configuration["AppSettings:jwt:issuer"],
            ValidAudiences = audiences,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AppSettings:jwt:key"])),
            
        };
    });

    services.AddAuthorization(auth =>
    {
        auth.AddPolicy("Bearer", 
            new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser().Build());
    });

    services.AddCors(options =>
    {
        options.AddPolicy("CorsPolicy",
            builder => builder.AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials().Build());
    });

    services.AddHttpContextAccessor();

    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
}
```

Este método primeiramente configura a autenticação desta <i><b>Web-API</b></i> com os parâmetros padrão para a utilização de Tokens JWT.

Após isto são feitas as configurações sobre a autorização da <i><b>Web-API</b></i> via dados fornecidos pelo Token recebido. 

Serão validados os seguintes aspectos dos Token:

1. Issuer
1. Audience
1. Tempo de vida
1. Chave de assinatura do Issuer

Também é configurado o acesso via <i>Cross-Origin Requests</i> e as configurações necessárias para viabilizar o acesso aos dados do usuário armazenados no Token.

#### Alterar método de configuração da aplicação

O método nomeado <i>Configure</i> deverá ser alterado conforme trecho de código abaixo par habilitar a autenticação e o uso de <i><b>CORS</b></i>.

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseMvc();
    app.UseAuthentication();
    app.UseCors("CorsPolicy");
}
```

### Criar <i>controller</i> <b>AspNetCore MVC</b> para disponibilização dos métodos com execução autorizada por roles fornecidos via Token JWT

Criar clase <i>controller</i> <b>MVC</b> nomeada SecuredController que deverá expor dois métodos que somente poderão ser executados caso o usuário identificado via Token <b>JWT</b> recebido contenha os <i>roles</i> designados. Os métodos deverão retornar as <i>claims</i> do usuário identificado via Token <b>JWT</b>.

```csharp
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
```

Agora podemos acessar o método MetodoSeguroAdministrador ou MetodoSegurousuario através dos sítios <http://localhost:7000/api/secured/administrador> e <http://localhost:7000/api/secured/usuario> passando no header o Bearer Token obtido através do <b>JWT</b> <i>issuer</i> descrito no projeto <https://git.serpro/ComponentesDotNet/dotnetcoreidentityserverjwtissuer>. 

Caso o Token seja válido e o usuário possua uma <i>Claim</i> de tipo <i>Role</i> com o valor "administrador" ou "usuário" o retorno deverá ser similar ao retorno abaixo:

```json
{
    "mensagem": "Método que somente token com usuário com role 'administrador' pode acessar. USUARIO: name: 029ad026-fd6e-4207-909a-f78c60f7bef7, authenticated: True, claims:((Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name, value: 029ad026-fd6e-4207-909a-f78c60f7bef7), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name, value: admin@serpro.gov.br), (Type: iss, value: http://localhost:6000/), (Type: jti, value: 36e408be303d4d4d9cc6aa074eee1070), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier, value: 029ad026-fd6e-4207-909a-f78c60f7bef7), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress, value: admin@serpro.gov.br), (Type: exp, value: 1555546036), (Type: nbf, value: 1555509436), (Type: auth_time, value: 1555509436), (Type: aud, value: audience1), (Type: http://schemas.microsoft.com/ws/2008/06/identity/claims/role, value: administrador), (Type: iat, value: 1555509436), )"
}
```

Caso o Token seja inválido ou o usuário não possua as credenciais supracitadas o retorno deverá ser HTTP Forbidden (403).
