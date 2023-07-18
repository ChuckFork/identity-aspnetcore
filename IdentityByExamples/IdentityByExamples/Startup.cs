using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoMapper;
using EmailService;
using IdentityByExamples.CustomTokenProviders;
using IdentityByExamples.CustomValidators;
using IdentityByExamples.Factory;
using IdentityByExamples.Models;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

namespace IdentityByExamples
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationContext>(opts =>
                opts.UseSqlServer(Configuration.GetConnectionString("sqlConnection")));

            services.AddIdentity<User, IdentityRole>(opt =>
            {
                opt.Password.RequiredLength = 7;
                opt.Password.RequireDigit = false;
                opt.Password.RequireUppercase = false;
                opt.Password.RequireNonAlphanumeric = false;

                opt.User.RequireUniqueEmail = true;

                //opt.SignIn.RequireConfirmedEmail = true;

                opt.Tokens.EmailConfirmationTokenProvider = "emailconfirmation";

                opt.Lockout.AllowedForNewUsers = true;
                opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
                opt.Lockout.MaxFailedAccessAttempts = 3;
            })
             .AddEntityFrameworkStores<ApplicationContext>()
             .AddDefaultTokenProviders()
             .AddTokenProvider<EmailConfirmationTokenProvider<User>>("emailconfirmation")
             .AddPasswordValidator<CustomPasswordValidator<User>>();

            services.Configure<DataProtectionTokenProviderOptions>(opt =>
               opt.TokenLifespan = TimeSpan.FromHours(2));

            services.Configure<EmailConfirmationTokenProviderOptions>(opt =>
                opt.TokenLifespan = TimeSpan.FromDays(3));

            services.AddScoped<IUserClaimsPrincipalFactory<User>, CustomClaimsFactory>();

            //services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
            services.AddAuthentication()
                .AddGoogle("Google", opt =>
                {
                    var googleAuth = Configuration.GetSection("Authentication:Google");

                    opt.ClientId = googleAuth["ClientId"];
                    opt.ClientSecret = googleAuth["ClientSecret"];
                    opt.SignInScheme = IdentityConstants.ExternalScheme;
 
                })
                .AddMicrosoftIdentityWebApp(options => {
                    options.ClientId = Configuration["Authentication:AzureAd:ClientId"];
                    options.ClientSecret = Configuration["Authentication:AzureAd:ClientSecret"];
                    options.Instance = Configuration["Authentication:AzureAd:Instance"];
                    options.Domain = Configuration["Authentication:AzureAd:Domain"];
                    options.TenantId = Configuration["Authentication:AzureAd:TenantId"];
                    //options.ClientCertificates = Configuration.GetSection("Authentication:AzureAd:ClientCertificates").Get<X509Certificate2[]>();
                    options.CallbackPath = Configuration["Authentication:AzureAd:CallbackPath"];
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.Events.OnRedirectToIdentityProvider = OnRedirectToIdentityProvider;
                    options.Events.OnRedirectToIdentityProviderForSignOut = OnRedirectToIdentityProviderForSignOutFuc;
                },cookieScheme:null);
            //services.AddControllersWithViews(options =>
            //{
            //    var policy = new AuthorizationPolicyBuilder()
            //        .RequireAuthenticatedUser()
            //        .Build();
            //    options.Filters.Add(new AuthorizeFilter(policy));
            //}).AddMicrosoftIdentityUI();

            services.AddRazorPages().AddMicrosoftIdentityUI();

            services.AddAutoMapper(typeof(Startup));

            var emailConfig = Configuration
                .GetSection("EmailConfiguration")
                .Get<EmailConfiguration>();
            services.AddSingleton(emailConfig);
            services.AddScoped<IEmailSender, EmailSender>();

            services.AddControllersWithViews();
        }

        private async Task OnRedirectToIdentityProvider(RedirectContext arg)
        {
            // use "prompt" parameter during authorize request, the value "select_account" allows the user to select the account to sign in
            arg.Options.Prompt = "select_account";
            await Task.CompletedTask.ConfigureAwait(false);
        }
        private async Task OnRedirectToIdentityProviderForSignOutFuc(RedirectContext arg)
        {
            arg.HttpContext.Session.Clear();
            await Task.CompletedTask.ConfigureAwait(false);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
