using Microsoft.Extensions.DependencyInjection;
using System;

namespace PosixPermissions.Extensions
{
    /// <summary>
    /// Provides an extension method to the <see cref="ServiceCollection"/> class, that initializes all dependencies used throughout the main library.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Enables the POSIX permission service.
        /// </summary>
        /// <param name="serviceCollection">Service collection to add the POSIX permission service.</param>
        public static void AddPosixAcls(this ServiceCollection serviceCollection)
        {
            if(serviceCollection == null)
                throw new ArgumentNullException(nameof(serviceCollection));

            serviceCollection.AddTransient<INativeLibraryInterface, NativeLibraryInterface>();
            serviceCollection.AddTransient<IPosixPermissionsProvider, PosixPermissionsProvider>();
        }
    }
}
