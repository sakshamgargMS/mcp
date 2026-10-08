// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Microsoft.Mcp.Core.Commands;
using Microsoft.Mcp.Core.Helpers;
using Microsoft.Mcp.Core.Models.Command;

namespace Azure.Mcp.Core.Services.Azure;

/// <summary>
/// Validates the final SDK ARM request before transport and recording-proxy rewriting.
/// </summary>
/// <param name="armEnvironment">The configured Azure cloud against which ARM endpoints are validated.</param>
/// <param name="contextAccessor">The host's singleton accessor for the currently executing command.</param>
/// <remarks>
/// Add at <see cref="HttpPipelinePosition.BeforeTransport"/> to inspect the final request URI
/// on each transport attempt, including retries, paging, and long-running-operation polling.
/// Validation occurs before HTTP handlers rewrite valid requests to a recording proxy.
/// <para>
/// This policy can live as long as a cached ARM client: it stores the accessor, not an invocation's
/// namespace. Every send validates, including direct CLI and background work using this pipeline.
/// A missing context or unresolved namespace is passed to the validator as null and cannot
/// use a namespace-scoped bypass, including ALL. Independently constructed ARM clients and
/// raw HTTP requests without this policy are outside its scope.
/// </para>
/// </remarks>
internal sealed class ArmUriValidationPipelinePolicy(
    ArmEnvironment armEnvironment,
    ICommandContextAccessor contextAccessor) : HttpPipelineSynchronousPolicy
{
    /// <summary>
    /// Validates this attempt's ARM URI using the current command's original tool namespace.
    /// </summary>
    /// <param name="message">The pipeline message containing the final request to send.</param>
    /// <remarks>
    /// Called for synchronous and asynchronous sends by <see cref="HttpPipelineSynchronousPolicy"/>.
    /// Uses endpoint service type <c>arm</c> independently of the command's tool namespace.
    /// Validation exceptions propagate to command error handling without sending the denied request.
    /// </remarks>
    /// <exception cref="System.Security.SecurityException">
    /// The endpoint is rejected by ARM validation and no applicable namespace bypass is configured.
    /// </exception>
    public override void OnSendingRequest(HttpMessage message)
    {
        // Cached ARM resources retain their pipelines across tool calls; never capture the creating namespace.
        CommandContext? context = contextAccessor.CurrentContext;

        // EndpointValidator will decide what to do if we can't give it a
        // tool namespace being executed.
        EndpointValidator.ValidateAzureServiceEndpoint(
            endpoint: message.Request.Uri.ToUri().AbsoluteUri,
            serviceType: "arm",
            armEnvironment: armEnvironment,
            executingToolNamespaceName: context?.ToolNamespaceName);
    }
}
