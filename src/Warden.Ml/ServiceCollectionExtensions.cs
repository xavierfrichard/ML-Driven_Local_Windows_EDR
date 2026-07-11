using Microsoft.Extensions.DependencyInjection;
using Warden.Core;

namespace Warden.Ml;

/// <summary>DI registration for the ML (ONNX) verdict tier.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenMl(this IServiceCollection services, Action<MlOptions>? configure = null)
    {
        var options = new MlOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<IPeFeatureExtractor, EmberFeatureExtractor>();
        services.AddSingleton<OnnxScorer>();
        services.AddSingleton<IVerdictSource>(sp => sp.GetRequiredService<OnnxScorer>());
        return services;
    }
}
