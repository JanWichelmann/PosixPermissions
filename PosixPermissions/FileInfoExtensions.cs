using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Contains extension methods for the <see cref="FileInfo"/> and <see cref="DirectoryInfo"/> classes.
    /// </summary>
    public static class SystemIoExtensions
    {
        /// <summary>
        /// Returns the permission data (owner and ACL) of the file.
        /// </summary>
        /// <param name="fileInfo">The <see cref="FileInfo"/> object describing the file to retrieve the permission data for.</param>
        public static FilePermissionInfo GetPermissions(this FileInfo fileInfo)
        {
            // Read permissions
            return new FilePermissionInfo(fileInfo);
        }

        /// <summary>
        /// Applies the given permission data to the file.
        /// </summary>
        /// <param name="fileInfo">The <see cref="FileInfo"/> object describing the file to apply the permission data to.</param>
        /// <param name="filePermissionInfo">The <see cref="FilePermissionInfo"/> object to apply.</param>
        public static void SetPermissions(this FileInfo fileInfo, FilePermissionInfo permissionInfo)
        {
            // Write permissions
            permissionInfo.ApplyPermissions(fileInfo);
        }

        /// <summary>
        /// Returns the permission data (owner and ACL) of the directory.
        /// </summary>
        /// <param name="directoryInfo">The <see cref="DirectoryInfo"/> object describing the directory to retrieve the permission data for.</param>
        public static FilePermissionInfo GetPermissions(this DirectoryInfo directoryInfo)
        {
            // Read permissions
            return new FilePermissionInfo(directoryInfo, false);
        }

        /// <summary>
        /// Applies the given permission data to the directory.
        /// </summary>
        /// <param name="directoryInfo">The <see cref="DirectoryInfo"/> object describing the directory to apply the permission data to.</param>
        /// <param name="filePermissionInfo">The <see cref="FilePermissionInfo"/> object to apply.</param>
        public static void SetPermissions(this DirectoryInfo directoryInfo, FilePermissionInfo permissionInfo)
        {
            // Write permissions
            permissionInfo.ApplyPermissions(directoryInfo, false);
        }

        /// <summary>
        /// Returns the default permission data (owner and default ACL) of the directory.
        /// </summary>
        /// <param name="directoryInfo">The <see cref="DirectoryInfo"/> object describing the directory to retrieve the permission data for.</param>
        public static FilePermissionInfo GetDefaultPermissions(this DirectoryInfo directoryInfo)
        {
            // Read permissions
            return new FilePermissionInfo(directoryInfo, true);
        }

        /// <summary>
        /// Applies the given default permission data to the directory.
        /// </summary>
        /// <param name="directoryInfo">The <see cref="DirectoryInfo"/> object describing the directory to apply the permission data to.</param>
        /// <param name="filePermissionInfo">The <see cref="FilePermissionInfo"/> object to apply.</param>
        public static void SetDefaultPermissions(this DirectoryInfo directoryInfo, FilePermissionInfo permissionInfo)
        {
            // Write permissions
            permissionInfo.ApplyPermissions(directoryInfo, true);
        }
    }
}
