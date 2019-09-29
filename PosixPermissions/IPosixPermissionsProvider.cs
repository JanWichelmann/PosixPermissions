using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Defines utility methods that create <see cref="PosixPermissionInfo"/> objects through dependency injection.
    /// </summary>
    public interface IPosixPermissionsProvider
    {
        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object with an empty access control list for the given owner and group.
        /// </summary>
        /// <param name="ownerId">The UID of the file's owner.</param>
        /// <param name="groupId">The GID of the file's group.</param>
        PosixPermissionInfo CreateEmptyPosixPermissionInfo(int ownerId, int groupId);

        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object from the given file.
        /// </summary>
        /// <param name="file">The file to load the permissions for.</param>
        PosixPermissionInfo GetPosixPermissionInfo(FileInfo file);

        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object from the given directory.
        /// </summary>
        /// <param name="directory">The directory to load the permissions for.</param>
        /// <param name="loadDefaultAcl">Specifies whether the directory's own or default ACL should be loaded.</param>
        PosixPermissionInfo GetPosixPermissionInfo(DirectoryInfo directory, bool loadDefaultAcl);
    }
}
