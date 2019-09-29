using System;
using System.IO;

namespace PosixPermissions
{
    /// <summary>
    /// Provides utility methods to create <see cref="PosixPermissionInfo"/> objects through dependency injection.
    /// </summary>
    public class PosixPermissionsProvider : IPosixPermissionsProvider
    {
        /// <summary>
        /// Object for native operations.
        /// </summary>
        private readonly INativeLibraryInterface _nativeLibraryInterface;

        /// <summary>
        /// Creates a new <see cref="PosixPermissionsProvider"/> object with the given injected objects.
        /// </summary>
        /// <param name="nativeLibraryInterface">Object for native operations.</param>
        public PosixPermissionsProvider(INativeLibraryInterface nativeLibraryInterface)
        {
            _nativeLibraryInterface = nativeLibraryInterface ?? throw new ArgumentNullException(nameof(nativeLibraryInterface));
        }

        /// <inheritdoc />
        public PosixPermissionInfo CreateEmptyPosixPermissionInfo(int ownerId, int groupId)
            => new PosixPermissionInfo(_nativeLibraryInterface, ownerId, groupId);

        /// <inheritdoc />
        public PosixPermissionInfo GetPosixPermissionInfo(FileInfo file)
            => new PosixPermissionInfo(_nativeLibraryInterface, file);

        /// <inheritdoc />
        public PosixPermissionInfo GetPosixPermissionInfo(DirectoryInfo directory, bool loadDefaultAcl)
            => new PosixPermissionInfo(_nativeLibraryInterface, directory, loadDefaultAcl);
    }
}