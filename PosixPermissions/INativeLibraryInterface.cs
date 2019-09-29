namespace PosixPermissions
{
    /// <summary>
    /// Interface for communication with the underlying native library.
    /// </summary>
    public interface INativeLibraryInterface
    {
        /// <summary>
        /// Queries the permission data and ACL of the given file or directory.
        /// </summary>
        /// <param name="fileName">The file or directory to query.</param>
        /// <param name="loadDefaultAcl">Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        /// <param name="dataContainer">Pointer to container object to store retrieved permissions and assoiated meta data.</param>
        AccessControlListEntry[] GetPermissionData(string fileName, int loadDefaultAcl, out NativePermissionDataContainer dataContainer);

        /// <summary>
        /// Sets the permission data and ACL of the given file or directory.
        /// </summary>
        /// <param name="fileName">The file or directory to set permissions for.</param>
        /// <param name="setDefaultAcl">Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        /// <param name="dataContainer">Pointer to container object with permissions and meta data.</param>
        /// <param name="entries">Entries of the object' new access control list.</param>
        void SetPermissionData(string fileName, int setDefaultAcl, ref NativePermissionDataContainer dataContainer, AccessControlListEntry[] entries);
    }
}