using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PosixPermissions
{
    public partial class FilePermissionInfo
    {
        /// <summary>
        /// Loads the permission data from the given file or directory.
        /// </summary>
        /// <param name="fullPath">Full path to the file or directory.</param>
        /// <param name="loadDefaultAcl">Specifies whether to load a directory's default ACL (1) or not (0). This must be 0 for files.</param>
        private FilePermissionInfo(string fullPath, int loadDefaultAcl)
        {
            // Get permission data
            // TODO handle/document exceptions
            var acl = NativeInterface.GetPermissionData(fullPath, loadDefaultAcl, out var dataContainer);

            // Initialize members
            OwnerId = dataContainer.OwnerId;
            OwnerPermissions = dataContainer.OwnerPermissions;
            GroupId = dataContainer.GroupId;
            GroupPermissions = dataContainer.GroupPermissions;
            OtherPermissions = dataContainer.OtherPermissions;

            // Parse ACL
            foreach(var entry in acl)
            {
                switch(entry.TagType)
                {
                    case AccessControlListEntryTagTypes.User:
                    {
                        // Add user to list
                        if(entry.TagQualifier != OwnerId)
                            _aclUserPermissions[entry.TagQualifier] = entry.Permissions;

                        break;
                    }

                    case AccessControlListEntryTagTypes.Group:
                    {
                        // Add group to list
                        if(entry.TagQualifier != GroupId)
                            _aclGroupPermissions[entry.TagQualifier] = entry.Permissions;

                        break;
                    }

                    default:
                    {
                        // Skip
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Creates a new <see cref="FilePermissionInfo"/> object from the given file.
        /// </summary>
        /// <param name="file">The file to load the permissions for.</param>
        public FilePermissionInfo(FileInfo file)
            : this(file.FullName, 0)
        { }

        /// <summary>
        /// Creates a new <see cref="FilePermissionInfo"/> object from the given directory.
        /// </summary>
        /// <param name="directory">The directory to load the permissions for.</param>
        /// <param name="loadDefaultAcl">Specifies whether the directory's own or default ACL should be loaded.</param>
        public FilePermissionInfo(DirectoryInfo directory, bool loadDefaultAcl)
            : this(directory.FullName, loadDefaultAcl ? 0 : 1)
        { }

        /// <summary>
        /// Applies the contained permissions to the given file.
        /// </summary>
        /// <param name="file">The file to apply the permissions to.</param>
        public void ApplyPermissions(FileInfo file)
        {

            // TODO handle/document exceptions
        }

        /// <summary>
        /// Applies the contained permissions to the given directory.
        /// </summary>
        /// <param name="directory">The directory to apply the permissions to.</param>
        /// <param name="asDefault">Specifies whether the permissions shall be stored as the directory's default ACL.</param>
        public void ApplyPermissions(DirectoryInfo directory, bool asDefault)
        {

            // TODO handle/document exceptions
        }
    }
}
