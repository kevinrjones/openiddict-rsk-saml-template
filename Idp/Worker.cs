using Microsoft.AspNetCore.Identity;
using MySqlConnector;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using Rsk.Saml;
using Rsk.Saml.IdentityProvider.Storage.EntityFramework;
using Rsk.Saml.IdentityProvider.Storage.EntityFramework.DbContexts;
using Rsk.Saml.IdentityProvider.Storage.EntityFramework.Mappers;
using Rsk.Saml.Models;
using Rsk.Saml.OpenIddict.EntityFrameworkCore.DbContexts;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using Rsk.Saml.OpenIddict.Extensions;
using IdP.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;
using ServiceProvider = Rsk.Saml.Models.ServiceProvider;

namespace IdP;

public class Worker : IHostedService
{
    
    private const string TestUsername = "bob@test.fake";
    private const string TestUserEmail = "bob@test.fake";
    private const string TestUserPassword = "Password123!";
    
    private readonly IServiceProvider _serviceProvider;

    public Worker(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        
        await CreateTestUser(scope);
        await CreateTestClient(scope);
        await CreateTestServiceProvider(scope);
        await CreateOIDCScopes(scope);

        await SaveAllChanges(scope);
    }

    private async Task CreateTestServiceProvider(AsyncServiceScope scope)
    {
        var entityId = "https://localhost:5003/saml";
        await CreateServiceProviderIfNotExists(scope, entityId, conf =>
        {
            conf.EntityId = entityId;
            conf.EncryptAssertions = false;
            conf.SignAssertions = false;
            conf.RequireAuthenticationRequestsSigned = false;

            conf.AssertionConsumerServices = [
                new Service(SamlConstants.BindingTypes.HttpPost, "https://localhost:5003/signin-saml-openIddict")
            ];

            conf.SingleLogoutServices = [
                new Service(SamlConstants.BindingTypes.HttpRedirect, "https://localhost:5003/signout-saml")
            ];
        });
    }

    private async Task CreateTestClient(AsyncServiceScope scope)
    {
        var clientId = "https://localhost:5003/saml";
        await CreateClientIfNotExists(scope, clientId, conf =>
        {
            conf.ClientId = clientId;
            conf.Permissions.Add(Permissions.Scopes.Email);
        });
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private Task CreateTestUser(IServiceScope scope)
    {
        if (!string.IsNullOrWhiteSpace(TestUsername) && 
            !string.IsNullOrWhiteSpace(TestUserEmail) &&
            !string.IsNullOrWhiteSpace(TestUserPassword)
            )
        {
            return CreateUserIfNotExists(scope, TestUsername, user =>
            {
                user.UserName = TestUsername;
                user.Email = TestUserEmail;
            }, TestUserPassword);
        }
        
        return Task.CompletedTask;
    }

    private async Task CreateOIDCScopes(IServiceScope scope)
    {
        await CreateScopeIfNotExists(scope, Scopes.Email, x =>
        {
            x.Name = Scopes.Email;
            x.AddClaimTypes(JwtClaimTypes.Email);
        });

        await CreateScopeIfNotExists(scope, Scopes.Profile, x =>
        {
            x.Name = Scopes.Profile;
            x.AddClaimTypes(
                JwtClaimTypes.Name,
                JwtClaimTypes.FamilyName,
                JwtClaimTypes.NickName,
                JwtClaimTypes.GivenName,
                JwtClaimTypes.MiddleName,
                JwtClaimTypes.Picture, JwtClaimTypes.UpdatedAt
            );
        });

        await CreateScopeIfNotExists(scope, Scopes.Roles, x =>
        {
            x.Name = Scopes.Roles;
            x.AddClaimTypes(JwtClaimTypes.Role);
        });
    }
    
    private async Task CreateUserIfNotExists(IServiceScope scope, string userName,
        Action<ApplicationUser> userConfiguration, string userPassword)
    {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        if (await userManager.FindByNameAsync(userName) == null)
        {
            var user = new ApplicationUser();
            userConfiguration(user);
            await userManager.CreateAsync(user, userPassword);
        }
    }

    private async Task CreateClientIfNotExists(IServiceScope scope, string clientId,
        Action<OpenIddictApplicationDescriptor> descriptorConfiguration)
    {
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await manager.FindByClientIdAsync(clientId) == null)
        {
            var newClientDescriptor = new OpenIddictApplicationDescriptor();
            descriptorConfiguration(newClientDescriptor);
            
            await manager.CreateAsync(newClientDescriptor);
        }
    }
    
    private async Task CreateServiceProviderIfNotExists(IServiceScope scope, string entityId,
        Action<ServiceProvider> serviceProviderConfiguration)
    {
        var samlConfigurationDbContext = scope.ServiceProvider.GetRequiredService<ISamlConfigurationDbContext>();

        if (await samlConfigurationDbContext.ServiceProviders.SingleOrDefaultAsync(x => x.EntityId == entityId) == null)
        {
            var serviceProvider = new ServiceProvider();
            serviceProviderConfiguration(serviceProvider);
            samlConfigurationDbContext.ServiceProviders.Add(serviceProvider.ToEntity());
        }
    }
    
    private async Task CreateScopeIfNotExists(IServiceScope scope, string scopeName,
        Action<OpenIddictScopeDescriptor> scopeConfiguration)
    {
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        if (await scopeManager.FindByNameAsync(scopeName) == null)
        {
            var scopeDescriptor = new OpenIddictScopeDescriptor();
            scopeConfiguration(scopeDescriptor);

            await scopeManager.CreateAsync(scopeDescriptor);
        }
    }
    
    private async Task SaveAllChanges(IServiceScope scope)
    {
        var samlConfigurationDbContext = scope.ServiceProvider.GetRequiredService<ISamlConfigurationDbContext>();
        await samlConfigurationDbContext.SaveChangesAsync();
    }
}