// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Mcp.Core.Commands;
using Microsoft.Mcp.Core.Helpers;
using Microsoft.Mcp.Core.Models.Command;
using Microsoft.Mcp.Core.Services.Http;
using Microsoft.Security.AntiSSRF;
using Xunit;

namespace Microsoft.Mcp.Core.Tests.Services.Http;

/// <summary>Runs separately from other write-once override tests.</summary>
[Trait("TestType", "Isolated")]
public sealed class AllNamespaceHttpBypassTests
{
    [Fact(Explicit = true)]
    public async Task All_RequiresResolvedContextAndDoesNotChangeExplicitNamedClient()
    {
        EndpointValidator.SetDangerouslyDisabledSsrfProtectionNamespaces(["all"]);
        await using LoopbackHttpServer server = LoopbackHttpServer.Start();
        using ServiceProvider provider = AntiSsrfHttpClientTests.CreateProvider();
        ICommandContextAccessor accessor = provider.GetRequiredService<ICommandContextAccessor>();
        IHttpClientFactory factory = provider.GetRequiredService<IHttpClientFactory>();
        using HttpClient client = factory.CreateClient();
        using (accessor.BeginScope(new CommandContext { ToolNamespaceName = "storage" }))
        {
            using HttpResponseMessage response = await client.GetAsync(server.Endpoint, TestContext.Current.CancellationToken);
            Assert.True(response.IsSuccessStatusCode);
        }

        foreach (string? namespaceName in new string?[] { null, "", " " })
        {
            using (accessor.BeginScope(new CommandContext { ToolNamespaceName = namespaceName }))
            {
                await Assert.ThrowsAsync<AntiSSRFException>(() =>
                    client.GetAsync(server.Endpoint, TestContext.Current.CancellationToken));
            }
        }

        await Assert.ThrowsAsync<AntiSSRFException>(() =>
            client.GetAsync(server.Endpoint, TestContext.Current.CancellationToken));
        using HttpClient unprotected = factory.CreateClient(HttpClientFactoryConfigurator.NoSsrfClientName);
        using HttpResponseMessage unprotectedResponse = await unprotected.GetAsync(server.Endpoint, TestContext.Current.CancellationToken);
        Assert.True(unprotectedResponse.IsSuccessStatusCode);
        Assert.Equal(2, server.Requests.Count);
    }
}
