// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Mcp.Core.Areas.Server;
using Microsoft.Mcp.Core.Commands;
using Microsoft.Mcp.Core.Models.Command;
using Microsoft.Mcp.Core.Services.Http;
using Microsoft.Security.AntiSSRF;
using Xunit;

namespace Microsoft.Mcp.Core.Tests.Services.Http;

public sealed class AntiSsrfHttpClientTests
{
    [Theory]
    [InlineData("")]
    [InlineData("custom")]
    [InlineData(HttpClientFactoryConfigurator.ArmClientName)]
    public async Task Factory_DefaultAndNamedClientsRejectPlainHttp(string name)
    {
        using ServiceProvider provider = CreateProvider();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(name);
        await Assert.ThrowsAsync<AntiSSRFException>(() =>
            client.GetAsync("http://127.0.0.1", TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("https://127.0.0.1", false)]
    [InlineData("https://localhost", false)]
    [InlineData("https://[::1]", false)]
    [InlineData("https://10.0.0.1", false)]
    [InlineData("https://169.254.169.254", false)]
    [InlineData("https://127.0.0.1", true)]
    [InlineData("https://localhost", true)]
    public async Task Factory_RejectsPrivateDnsAndIpBeforeConnecting(string endpoint, bool synchronous)
    {
        using ServiceProvider provider = CreateProvider();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        if (synchronous)
        {
            Assert.Throws<AntiSSRFException>(() => client.Send(request, TestContext.Current.CancellationToken));
        }
        else
        {
            await Assert.ThrowsAsync<AntiSSRFException>(() =>
                client.SendAsync(request, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task Factory_ExplicitUnprotectedClientRetainsDefaultsAndCanReachLoopback()
    {
        await using LoopbackHttpServer server = LoopbackHttpServer.Start();
        using ServiceProvider provider = CreateProvider();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(HttpClientFactoryConfigurator.NoSsrfClientName);
        using HttpResponseMessage response = await client.GetAsync(server.Endpoint, TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal(TimeSpan.FromSeconds(42), client.Timeout);
        Assert.NotEmpty(client.DefaultRequestHeaders.UserAgent);
        Assert.DoesNotContain("X-Forwarded-For", Assert.Single(server.Requests), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Factory_RecordingProxyOverridesIpProtectionButPreservesUpstream()
    {
#if DEBUG
        await using LoopbackHttpServer server = LoopbackHttpServer.Start();
        using ServiceProvider provider = CreateProvider(() => server.Endpoint);
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(HttpClientFactoryConfigurator.ArmClientName);
        using HttpResponseMessage response = await client.GetAsync("https://management.azure.com/test", TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
        string request = Assert.Single(server.Requests);
        Assert.Contains("GET /test", request);
        Assert.Contains("x-recording-upstream-base-uri: https://management.azure.com/", request, StringComparison.OrdinalIgnoreCase);
#else
        await Task.CompletedTask;
#endif
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Factory_ConfiguredProxyAndExclusionsOmitProtection(bool bypassProxy)
    {
        await using LoopbackHttpServer server = LoopbackHttpServer.Start();
        var services = new ServiceCollection();
        services.AddLogging().AddHttpClient();
        services.Configure<HttpClientOptions>(options =>
        {
            options.AllProxy = server.Endpoint.AbsoluteUri;
            options.NoProxy = bypassProxy ? "127.0.0.1" : null;
        });
        services.Configure<ServerRuntimeConfiguration>(options => options.Transport = "stdio");
        services.ConfigureDefaultHttpClient();
        using ServiceProvider provider = services.BuildServiceProvider();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
        Uri endpoint = bypassProxy ? server.Endpoint : new Uri("http://example.com/test");
        using HttpResponseMessage response = await client.GetAsync(endpoint, TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
        string request = Assert.Single(server.Requests);
        Assert.Contains(bypassProxy ? "GET / " : "GET http://example.com/test ", request);
    }

    [Fact]
    public async Task Factory_UnresolvedNamespaceDoesNotDisableProtection()
    {
        using ServiceProvider provider = CreateProvider();
        ICommandContextAccessor accessor = provider.GetRequiredService<ICommandContextAccessor>();
        using HttpClient client = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
        using (accessor.BeginScope(new CommandContext()))
        {
            await Assert.ThrowsAsync<AntiSSRFException>(() =>
                client.GetAsync("https://localhost", TestContext.Current.CancellationToken));
        }
    }

    /// <summary>Creates shared factory transports with no explicit HTTP proxy settings.</summary>
    /// <param name="recordingProxyResolver">An optional debug recording route; null uses ordinary transports.</param>
    /// <returns>A provider whose clients must be disposed before the provider.</returns>
    internal static ServiceProvider CreateProvider(Func<Uri?>? recordingProxyResolver = null)
    {
        var services = new ServiceCollection();
        services.AddLogging().AddHttpClient();
        services.Configure<HttpClientOptions>(options => options.DefaultTimeout = TimeSpan.FromSeconds(42));
        services.Configure<ServerRuntimeConfiguration>(options => options.Transport = "stdio");
        services.ConfigureArmHttpClient();
        services.ConfigureDefaultHttpClient(recordingProxyResolver ?? (() => null));
        return services.BuildServiceProvider();
    }
}
