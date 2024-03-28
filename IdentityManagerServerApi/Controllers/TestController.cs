using IdentityManagerServerApi;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace auth_ms_api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {

        [HttpPost("getRoute")]
        public IActionResult GetRoute([FromBody] object requestRoute)
        {

            dynamic appRoutes = JsonConvert.DeserializeObject(System.IO.File.ReadAllText("C:\\Users\\solna\\OneDrive\\Documents\\GitHub\\auth_ms\\IdentityManagerServerApi\\Data\\routes.json"));
            dynamic req = JsonConvert.DeserializeObject(requestRoute.ToString());

            try
            {
                var auth = HttpContext.Request.Headers.Authorization.ToString().Split(" ")[1];
            }
            catch
            {
                if (req["route"] == "/user" && req["method"] == "post") {
                    return Ok("Authorized");
                }
                else
                {
                    return Ok("Unauthorized");
                }

            }
            var authorization = HttpContext.Request.Headers.Authorization.ToString().Split(" ")[1];
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(authorization);
            var tokenS = jsonToken as JwtSecurityToken;
            var role = tokenS.Claims.ToArray()[3].Value.ToString();

            try
            {
                if (appRoutes[role][req["route"].ToString()]["method"].ToString().Contains(req["method"].ToString()))
                {
                    return Ok("Authorized");
                }
                else
                {
                    return Ok("Unauthorized");
                }
            }

            catch {
                return Ok("Enter a valid route");
            }
        }

    }
}
