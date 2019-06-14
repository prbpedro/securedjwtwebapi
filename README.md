# ASPNetCore - WEB-API with authorization based on role provided throw a JWT token

Through this tutorial you'll be able to create an aspnetcore 2.2 WEB-API that will provide two methods that return the information of the identified user throw a JWT token if the user has certain access Roles also identified in the Token.

Running this application requires that the date/time of the machine has the time value of Coordinate Universal Time (UTC).

## Creating an ASPNetCore 2.2 WEB-API project

1. Open the folder where you want the project to be in the VS Code
1. Create an ASPNetCore 2.2 WEB-API project throw running the below command in the Windows PowerShell Terminal in the VS Code

	```csharp
    dotnet new webapi
	```
	
### Editing the Program.cs class

You must include the call to the method UseUrls in the CreateWebHostBuilder delegate method. The execution of this method disables the HTTPS protocol on Kestrel and defines the entry URL of the WEB-API project created. 

In a productive environment the application must be acess throw the HTTPS protocol.

```csharp
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseUrls("http://localhost:7000");
```

### Editing the Startup.cs class

#### Including a constructor method that allows the configuration through a JSON file

Add the following contructor method in the Startup.cs class.

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

Include the following files in the root of the project:

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
Add the following XML code to the csproj file of the project to ensure the copy of the created files to the publication folder.

```xml	
<ItemGroup>
	<none Include="appsettings.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
    <none Include="appsettings.Development.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
</ItemGroup>
```
	
#### Changing the dependency injector configuration method

Modify the ConfigureServices method located in the Startup.cs as the below code.

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
First, this method will configure the authentication of this WEB-API with the default parameter to the use of JWT tokens.

After that, the method makes the configuration about the authorization of the WEB-API through the data provided by the received JWT token.

The following aspects of the JWT token will be validated:

1. Issuer
1. Audience
1. Token lifetime
1. Issuer signature key

The method also configures access through Cross-Origin Requests and access of the user data inside the JWT token.

#### Modifying the application configuration method

Modify the Configure method as the following code snippet to enable the authentication and the use of Cross-Origin Requests (CORS).

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseMvc();
    app.UseAuthentication();
    app.UseCors("CorsPolicy");
}
```

### Creating an AspNetCore MVC Controller to provide the methods with authorized execution by roles provided through JWT Token

Create an AspNetCore MVC Controller class, as the below code, named SecuredController that will expose two methods that can only be executed if the identified user through the received JWT token contains the designated roles.  The methods return the user claims identified through the JWT token.

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

Now you're able to call the methods MetodoSeguroAdministrador and MetodoSeguroUsuario through the sites <http://localhost:7000/api/secured/administrador> and <http://localhost:7000/api/secured/usuario> passing on the requisition header the bearer token got calling the JWT token issuer Login method described in the site <https://github.com/prbpedro/dotnetcoreidentityserverjwtissuer>.

If the passed JWT token is valid and the identified user has a claim typed as a role with the values "administrador" or "usuario" the return must be similar to the JSON text below:

```json
{
    "mensagem": "Método que somente token com usuário com role 'administrador' pode acessar. USUARIO: name: 029ad026-fd6e-4207-909a-f78c60f7bef7, authenticated: True, claims:((Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name, value: 029ad026-fd6e-4207-909a-f78c60f7bef7), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name, value: admin@serpro.gov.br), (Type: iss, value: http://localhost:6000/), (Type: jti, value: 36e408be303d4d4d9cc6aa074eee1070), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier, value: 029ad026-fd6e-4207-909a-f78c60f7bef7), (Type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress, value: admin@serpro.gov.br), (Type: exp, value: 1555546036), (Type: nbf, value: 1555509436), (Type: auth_time, value: 1555509436), (Type: aud, value: audience1), (Type: http://schemas.microsoft.com/ws/2008/06/identity/claims/role, value: administrador), (Type: iat, value: 1555509436), )"
}
```

If the JWT token is invalid or the user doesn't have the cited credentials the return will be an HTTP Forbidden (403) status code.
